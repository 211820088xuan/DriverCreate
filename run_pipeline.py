#!/usr/bin/env python3
"""
run_pipeline.py — Fuzz Driver 生成流水线（骨架驱动重构版）

流程:
  step1_prepare  →  [analyze_fuzzing_headers]  →  [skeleton_mine + plan_gen]
                                                     (Phase 6, 待实现)
                                                       │
                                                     step2_generate (per mode)
                                                     +L1-L4 校验
                                                       │
                                           agent_pipeline（--build, per mode）
                                           注入 → 构建 → 分诊 → 修复循环

三模式并列（focus/peer/cross），每模式 driver 落 output/<project>/<mode>/，
产物 oss-bin/<project>/<mode>/，互不覆盖。

step2 生成 driver 后默认停下。加 --build 跑多 agent 编译修复循环（agent_pipeline.py）：
主 agent 注入 build.sh/Dockerfile 标记块、构建、分诊失败 driver、分发给代码/编译修复 agent，
循环至全通过或达 max_rounds。无凭证时优雅降级（只注入+构建）。

用法:
  python run_pipeline.py <project> [--num-drivers=N] [--skip-llm] [--skip-headers]
                                    [--mode focus|peer|cross|all] [--build]
                                    [--max-rounds=N] [--log=PATH]
    --num-drivers=N  生成 N 个 driver/模式（默认 5）
    --skip-llm       跳过 step2（只做情报收集）
    --skip-headers   跳过 analyze_fuzzing_headers.py（默认开启，增强 step2 的头文件约束）
    --mode           focus|peer|cross|all（默认 all = 三模式都跑；Phase 8 step2 mode-aware 后生效）
    --build          跑 agent_pipeline 编译修复循环（每模式独立）
    --max-rounds=N   step3 修复循环最大轮数（默认 3）
                     （kill switch: 环境变量 DC_DISABLE_AGENT_REPAIR=1 → 只注入+构建，不修复）
"""

import sys
import subprocess
import os
from datetime import datetime
from pathlib import Path
from config import OUTPUT_DIR, PIPELINE_LOGS_DIR, MODES

SCRIPT_DIR = Path(__file__).resolve().parent


class _Tee:
    """同时写 stdout 和文件。"""
    def __init__(self, path):
        self._file = open(path, 'w', buffering=1, encoding='utf-8')
        self._stdout = sys.__stdout__

    def write(self, data):
        self._stdout.write(data)
        self._file.write(data)

    def flush(self):
        self._stdout.flush()
        self._file.flush()

    def close(self):
        self._file.close()

    def fileno(self):
        return self._stdout.fileno()


def run(script, project, args=None, fatal=False, module=None):
    """跑一个子步骤。module 非空时以 `python -m <module>` 形式调用（agent 包内模块用），
    否则按根目录脚本文件 `SCRIPT_DIR/<script>` 调用。统一 cwd=SCRIPT_DIR，
    保证子进程里 `from config import ...` / `from tools.step3_agent import ...` 能解析。"""
    label = module or script
    print(f"\n{'='*60}")
    print(f">>> {label}")
    print(f"{'='*60}")
    if module:
        cmd = [sys.executable, "-m", module, project]
    else:
        cmd = [sys.executable, str(SCRIPT_DIR / script), project]
    if args:
        cmd.extend(args)
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'
    result = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, bufsize=1, env=env, cwd=str(SCRIPT_DIR))
    for line in result.stdout:
        print(line, end="")
    result.wait()
    if result.returncode != 0:
        if fatal:
            sys.exit(1)
        print(f"  ⚠️ {label} 返回 {result.returncode}")
        return False
    return True


def _parse_args(argv):
    """解析命令行。返回 (project, opts)。

    opts 是 dict，键：
      skip_llm/skip_headers/build : bool
      num_drivers/max_rounds     : int
      modes                      : list[str]（focus/peer/cross 的非空子集）
      log_path                   : str|None
    """
    if not argv:
        print(__doc__)
        sys.exit(1)

    project = argv[0]
    flags, kv = set(), {}
    for a in argv[1:]:
        if a.startswith("--") and "=" in a:
            k, v = a.split("=", 1)
            kv[k] = v
        else:
            flags.add(a)

    mode_raw = kv.get("--mode", "all")
    if mode_raw == "all":
        modes = list(MODES)
    elif mode_raw in MODES:
        modes = [mode_raw]
    else:
        print(f"[error] --mode 非法: {mode_raw!r}（可选: focus|peer|cross|all）")
        sys.exit(1)

    opts = {
        "skip_llm": "--skip-llm" in flags,
        "skip_headers": "--skip-headers" in flags,
        "build": "--build" in flags,
        "num_drivers": int(kv.get("--num-drivers", "5")),
        "max_rounds": int(kv.get("--max-rounds", "3")),
        "modes": modes,
        "log_path": kv.get("--log"),
    }
    return project, opts


def _collect_summary(project):
    """扫描 output/<project>/（含 mode 子目录）汇总 driver 源文件与二进制。

    返回 (sources: list[Path], binaries: list[Path])。
    mode 子目录存在时递归扫；否则退回扁平布局（兼容历史数据）。
    """
    out_dir = OUTPUT_DIR / project
    sources = []
    for pat in ("*fuzzer*.c", "*fuzzer*.cpp", "*fuzzer*.cc", "*fuzzer*.cxx"):
        sources.extend(out_dir.rglob(pat))
    sources = [s for s in sources if "_fix_r" not in s.name]

    skip_suffixes = {'.c', '.cpp', '.cc', '.cxx', '.md', '.txt', '.json', '.log'}
    binaries = [b for b in out_dir.rglob("*") if b.is_file()
                and b.suffix not in skip_suffixes
                and '_compile_errors' not in b.name]
    return sources, binaries


def main():
    project, opts = _parse_args(sys.argv[1:])

    if opts["log_path"] is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        opts["log_path"] = str(PIPELINE_LOGS_DIR / f"pipeline_{project}_{ts}.log")

    os.makedirs(str(PIPELINE_LOGS_DIR), exist_ok=True)
    tee = _Tee(opts["log_path"])
    sys.stdout = sys.stderr = tee
    print(f"[log] {opts['log_path']}")
    print(f"项目: {project} | drivers/mode: {opts['num_drivers']} | "
          f"modes: {opts['modes']} | LLM: {not opts['skip_llm']} | "
          f"headers: {not opts['skip_headers']} | build: {opts['build']}"
          + (f" | max_rounds: {opts['max_rounds']}" if opts['build'] else ""))

    # ── Step 1: 情报收集（mode-agnostic，每项目一次）──
    run("step1_prepare.py", project, fatal=True)

    # ── 头文件白名单（mode-agnostic）──
    if not opts["skip_headers"]:
        run("tools/step1_tools/analyze_fuzzing_headers.py", project)  # 非致命

    # ── skeleton_mine（全局一次，产 skeletons.json；已存在则跳过）──
    from config import shared_dir
    skeletons_file = shared_dir() / "skeletons.json"
    if not skeletons_file.is_file():
        print("\n[Phase 6] skeleton_mine 全局挖骨架池（仅首次）...")
        run("tools/step0_tools/skeleton_mine.py", None, fatal=False)
    else:
        print(f"\n[Phase 6] skeletons.json 已存在（{skeletons_file}），跳过 skeleton_mine")

    # ── plan_gen（每项目一次，内部跑三模式；--num-drivers 是上限不是目标）──
    print(f"\n[Phase 6b] plan_gen {project}（三模式 plan_<mode>.json）...")
    run("tools/step2_tools/plan_gen.py", project, [str(opts["num_drivers"])], fatal=False)

    # ── Step 2: LLM 生成 driver（三模式）──
    if not opts["skip_llm"]:
        for m in opts["modes"]:
            run("step2_generate.py", project, [str(opts["num_drivers"]), f"--mode={m}"])

    # ── Step 3: 编译验证与修复（三模式顺序，共享 build.sh 不能并行）──
    if opts["build"]:
        for m in opts["modes"]:
            run("step3_build.py", project,
                args=[f"--mode={m}", f"--max-rounds={opts['max_rounds']}"])
    else:
        print(f"\n{'='*60}")
        print("  driver 已生成。下一步：")
        print(f"    python run_pipeline.py {project} --build")
        print(f"      → 跑第三阶段 step3_build.py（多 agent 编译修复循环）")
        print(f"    或手动跑第三阶段:")
        print(f"        python3 step3_build.py {project}              # 完整修复循环")
        print(f"        python3 step3_build.py {project} --no-repair  # 确定性兜底")
        print(f"{'='*60}")

    # ── 汇总（mode 子目录递归扫）──
    sources, binaries = _collect_summary(project)
    print(f"\n{'='*60}")
    print(f"  完成!")
    print(f"  生成: {len(sources)} 个 driver 源文件")
    print(f"  编译: {len(binaries)} 个二进制")
    print(f"{'='*60}")
    for b in sorted(binaries):
        rel = b.relative_to(OUTPUT_DIR / project) if b.is_relative_to(OUTPUT_DIR / project) else b
        print(f"  ✅ {rel}")


if __name__ == "__main__":
    main()