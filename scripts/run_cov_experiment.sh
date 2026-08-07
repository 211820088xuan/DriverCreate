#!/bin/bash
# run_cov_experiment.sh — 跑四组（origin/focus/peer/cross）coverage sanitizer 构建 + fuzz，产 .cov.json
#
# 流程（每项目）：
#   1. address sanitizer 构建（step3 build，已有）→ 产 oss-bin 二进制（crash 用）
#   2. coverage sanitizer 构建（本脚本，DC_SANITIZER=coverage DC_COV=1）→ 产 oss-bin-cov/<mode>/ 二进制
#   3. fuzz_runner --coverage 跑 → .profraw → .cov.json → artifacts/coverage_exp/<TS>/<proj>/<group>/
#   4. aggregate_coverage.py 跑 union-vs-k 曲线
#
# 用法：bash scripts/run_cov_experiment.sh <project> [--max-time=60] [--workers=2]
set -e

PROJECT="${1:?missing project}"
MAX_TIME=60
WORKERS=2
for a in "${@:2}"; do
    case $a in
        --max-time=*) MAX_TIME="${a#*=}" ;;
        --workers=*)  WORKERS="${a#*=}" ;;
    esac
done

DRIVER_CREATE_DIR="${DC_DRIVER_CREATE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
TS=$(date +%Y%m%d_%H%M%S)
RESULT_ROOT="$DRIVER_CREATE_DIR/artifacts/coverage_exp/$TS"

echo "[cov_exp] project=$PROJECT ts=$TS max_time=$MAX_TIME workers=$WORKERS"
mkdir -p "$RESULT_ROOT/$PROJECT"

# ── 1. coverage sanitizer 构建（三模式，提取到 oss-bin-cov/<mode>/）──
echo "[cov_exp] === 1. coverage sanitizer 构建（三模式）==="
for MODE in focus peer cross; do
    echo "[cov_exp] 构建 coverage: $MODE"
    # DC_SANITIZER=coverage → get_oss_fuzzer.sh 用 coverage sanitizer
    # DC_COV=1 → 提取到 oss-bin-cov/<mode>/（不覆盖 address 的 oss-bin/）
    DC_SANITIZER=coverage DC_COV=1 python3 "$DRIVER_CREATE_DIR/step3_build.py" "$PROJECT" \
        --mode="$MODE" --no-repair 2>&1 | tail -5 || echo "  [cov_exp] $MODE 构建失败（继续）"
done

# ── 2. origin 组：OSS-Fuzz 原始 driver 的 coverage ──
# origin = 项目自带 fuzzer（oss-fuzz/build/out/<proj>/*_fuzzer，非 *_crfuzzer）
# 需单独 coverage 构建（不注入 *_crfuzzer），这里先跳过，标记 origin 为 n/a
echo "[cov_exp] === 2. origin 组（OSS-Fuzz 原始 driver）==="
echo "  origin 需单独跑原始 driver coverage，当前标记 n/a"

# ── 3. 三组跑 fuzz_runner --coverage，产 .cov.json → coverage_exp/<TS>/<proj>/<group>/ ──
echo "[cov_exp] === 3. fuzz_runner --coverage 跑三组 ==="
for GROUP in focus peer cross; do
    OUT_DIR="$RESULT_ROOT/$PROJECT/$GROUP"
    mkdir -p "$OUT_DIR"
    # fuzz_runner --coverage 跑 oss-bin-cov/<group>/，产 covered_lines 在 fuzz_summary
    python3 "$DRIVER_CREATE_DIR/scripts/fuzz_runner.py" "$PROJECT" \
        --mode="$GROUP" --coverage --max-time="$MAX_TIME" --workers="$WORKERS" \
        2>&1 | tail -5 || echo "  [cov_exp] $GROUP fuzz 失败（继续）"
    # fuzz_summary.json 的 covered_lines 写成 .cov.json（每 binary 一份）
    python3 - "$PROJECT" "$GROUP" "$OUT_DIR" << 'PYEOF' || true
import json, sys, shutil
from pathlib import Path
proj, group, out_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
summary = Path(f"/root/gyx/driver_create/artifacts/output/{proj}/fuzz_summary.json")
if summary.is_file():
    data = json.load(open(summary))
    for r in data.get("results", []):
        if r.get("mode") == group and r.get("covered_lines"):
            (out_dir / f"{r['binary']}.cov.json").write_text(
                json.dumps({"covered_lines": r["covered_lines"]}))
    print(f"  [{group}] 写 .cov.json 到 {out_dir}")
PYEOF
done

echo "[cov_exp] === 4. aggregate_coverage.py 跑 union-vs-k ==="
python3 "$DRIVER_CREATE_DIR/tools/coverage_tools/aggregate_coverage.py" \
    "$RESULT_ROOT" 2>&1 | tail -20 || echo "  [cov_exp] aggregate 失败"

echo "[cov_exp] 完成 → $RESULT_ROOT"
