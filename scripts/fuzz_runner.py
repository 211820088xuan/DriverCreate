#!/usr/bin/env python3
"""
fuzz_runner.py — 跑 oss-bin 里的 *_crfuzzer 二进制做 libFuzzer fuzz，收集 crash

OSS-Fuzz 二进制要在 base-runner 容器里跑（host glibc 版本不够）。
对每个二进制：解压对应 seed_corpus.zip → docker run base-runner 跑 libFuzzer
→ crash 收集到 artifacts/crashes/<project>/[<mode>/]。

用法：
  python3 scripts/fuzz_runner.py <project> [--mode=<m>] [--max-time=300] [--workers=2]
  - --max-time: 每个 fuzzer 跑多少秒（默认 300）
  - --workers:  并行跑几个 fuzzer（默认 2，Docker 容器吃资源）
"""
import sys
import os
import json
import shutil
import subprocess
import zipfile
import tempfile
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

DRIVER_CREATE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(DRIVER_CREATE_DIR))
from config import OUTPUT_DIR, OSS_FUZZ_DIR, output_for, oss_bin_for, MODES

BASE_RUNNER_IMAGE = "gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04"
CRASHES_ROOT = OUTPUT_DIR  # artifacts/output/<project>/crashes/<mode>/


def find_binaries(project: str, mode: str | None, coverage: bool = False) -> list[Path]:
    """找 oss-bin/[cov/]<project>/[<mode>/] 下的 *_crfuzzer 二进制。"""
    if coverage:
        bin_dir = oss_bin_for(project, mode).parent.parent / "oss-bin-cov" / (mode or "")
    else:
        bin_dir = oss_bin_for(project, mode)
    if not bin_dir.is_dir():
        return []
    return sorted(f for f in bin_dir.iterdir()
                  if f.is_file() and os.access(f, os.X_OK) and "_crfuzzer" in f.name)


def prepare_corpus(project: str, binary: Path, work_dir: Path) -> Path:
    """为单个二进制准备 corpus 目录（解压 seed_corpus.zip，找不到则空目录）。"""
    stem = binary.name
    # seed_corpus.zip 在 oss-fuzz/build/out/<project>/<stem>_seed_corpus.zip
    # 或 oss-fuzz/build/out/<project>/ 下按名字匹配
    out_dir = OSS_FUZZ_DIR / "build" / "out" / project
    # 优先精确匹配 <stem>_seed_corpus.zip
    candidates = [
        out_dir / f"{stem}_seed_corpus.zip",
        out_dir / f"{stem.replace('_crfuzzer', '_fuzzer')}_seed_corpus.zip",
    ]
    corpus_zip = next((c for c in candidates if c.is_file()), None)

    corpus_dir = work_dir / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)
    if corpus_zip and corpus_zip.is_file():
        try:
            with zipfile.ZipFile(corpus_zip) as zf:
                zf.extractall(corpus_dir)
        except Exception as e:
            print(f"    [corpus] 解压 {corpus_zip.name} 失败: {e}")
    return corpus_dir


def run_one_fuzzer(project: str, binary: Path, mode: str | None,
                   max_time: int, crash_dir: Path,
                   coverage: bool = False) -> dict:
    """docker run base-runner 跑单个 fuzzer，返回结果。coverage 时额外产 .cov.json。"""
    work_dir = Path(tempfile.mkdtemp(prefix=f"fuzz_{binary.name}_"))
    try:
        corpus_dir = prepare_corpus(project, binary, work_dir)
        crash_dir.mkdir(parents=True, exist_ok=True)

        # docker run：挂载 oss-bin（含二进制）+ corpus + crash 目录
        bin_dir = binary.parent
        env_cov = []
        vol_cov = []
        cov_dir = None
        if coverage:
            cov_dir = work_dir / "cov"
            cov_dir.mkdir(exist_ok=True)
            env_cov = ["-e", f"LLVM_PROFILE_FILE=/cov/{binary.name}.%p.profraw"]
            vol_cov = ["-v", f"{cov_dir}:/cov"]
        cmd = [
            "docker", "run", "--rm",
            "--privileged", "--shm-size=2g",
            "--platform", "linux/amd64",
            "-e", "LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu",
        ] + env_cov + vol_cov + [
            "-v", f"{bin_dir}:/out:ro",
            "-v", f"{corpus_dir}:/corpus",
            "-v", f"{crash_dir}:/crashes",
            BASE_RUNNER_IMAGE,
            "bash", "-c",
            f"cd /out && ./{binary.name} /corpus "
            f"-max_total_time={max_time} "
            f"-rss_limit_mb=2048 "
            f"-artifact_prefix=/crashes/ "
            f"2>&1 | tail -20"
        ]
        t0 = time.time()
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=max_time + 120)
            elapsed = time.time() - t0
            out = (r.stdout or "")[-2000:]
        except subprocess.TimeoutExpired:
            elapsed = time.time() - t0
            out = f"[timeout after {max_time+120}s]"

        # 数 crash 文件
        crashes = sorted(f.name for f in crash_dir.iterdir()
                         if f.is_file() and f.name not in (".", ".."))
        result = {
            "binary": binary.name,
            "mode": mode or "flat",
            "elapsed": round(elapsed, 1),
            "crash_count": len(crashes),
            "crashes": crashes[:10],
            "tail": out[-500:],
        }
        # coverage：profraw → profdata → lcov → covered lines → .cov.json
        if coverage and cov_dir is not None:
            profraws = sorted(cov_dir.glob("*.profraw"))
            if profraws:
                profdata = work_dir / f"{binary.name}.profdata"
                lcov = work_dir / f"{binary.name}.lcov"
                # merge profraw → profdata
                subprocess.run(
                    ["llvm-profdata", "merge", "-o", str(profdata)]
                    + [str(p) for p in profraws],
                    capture_output=True, timeout=60)
                # export → lcov
                if profdata.is_file():
                    with open(lcov, "w") as lcov_f:
                        subprocess.run(
                            ["llvm-cov", "export", "-format=lcov",
                             str(binary), f"-instr-profile={profdata}"],
                            stdout=lcov_f, stderr=subprocess.DEVNULL, timeout=60)
                if lcov.is_file():
                    # 解析 lcov 的 covered lines（DA: <line>,<count> count>0 为覆盖）
                    covered = set()
                    for line in lcov.read_text(errors="ignore").splitlines():
                        if line.startswith("DA:"):
                            parts = line[3:].split(",")
                            if len(parts) >= 2 and int(parts[1]) > 0:
                                covered.add((parts[0] if len(parts) > 2 else "", int(parts[0])))
                    result["covered_lines"] = sorted(covered)
        return result
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    project = sys.argv[1]
    max_time = 300
    workers = 2
    mode = None
    coverage = False
    for a in sys.argv[2:]:
        if a.startswith("--mode="):
            mode = a.split("=", 1)[1]
        elif a.startswith("--max-time="):
            max_time = int(a.split("=", 1)[1])
        elif a.startswith("--workers="):
            workers = int(a.split("=", 1)[1])
        elif a == "--coverage":
            coverage = True

    modes = [mode] if mode else list(MODES)
    print(f"[fuzz] project={project} modes={modes} max_time={max_time}s workers={workers} coverage={coverage}")

    all_results = []
    for m in modes:
        bins = find_binaries(project, m, coverage=coverage)
        if not bins:
            print(f"  [{m}] 无二进制（oss-bin{'-cov' if coverage else ''}/{project}/{m}/ 空），跳过")
            continue
        crash_dir = CRASHES_ROOT / project / "crashes" / m
        crash_dir.mkdir(parents=True, exist_ok=True)
        print(f"  [{m}] {len(bins)} 个 fuzzer，crash → {crash_dir}")

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(run_one_fuzzer, project, b, m, max_time, crash_dir, coverage): b
                       for b in bins}
            for fut in as_completed(futures):
                res = fut.result()
                all_results.append(res)
                tag = f"[{res['mode']}]"
                print(f"    {tag} {res['binary']}: {res['crash_count']} crashes "
                      f"({res['elapsed']}s)")
                if res["crash_count"]:
                    print(f"      crashes: {res['crashes']}")

    # summary
    summary = {
        "project": project,
        "modes": modes,
        "max_time_per_fuzzer": max_time,
        "results": all_results,
        "total_crashes": sum(r["crash_count"] for r in all_results),
    }
    summary_path = OUTPUT_DIR / project / "fuzz_summary.json"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"\n[fuzz] done: {summary['total_crashes']} crashes total")
    print(f"  summary → {summary_path}")


if __name__ == "__main__":
    main()
