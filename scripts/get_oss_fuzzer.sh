#!/bin/bash
# ============================================================
# get_oss_fuzzer.sh — OSS-Fuzz 自定义 fuzzer 构建 & 提取脚本（不启动 fuzzer）
#
# 功能：
#   1. 构建指定项目的 fuzzers（build_image + build_fuzzers）
#   2. 从构建镜像中提取编译好的 *_crfuzzer 二进制到 oss-bin 目录
#
# 位置：driver_create/scripts/get_oss_fuzzer.sh（从 oss-fuzz 搬入本项目，
#       减少对 oss-fuzz 目录的散乱依赖；OSS_FUZZ_HOME 通过环境变量配置）
#
# 用法：
#   bash scripts/get_oss_fuzzer.sh <project> [dc_only_target] [mode]
#   - project:        项目名（必填）
#   - dc_only_target: 单编加速的目标 stem（可选）
#   - mode:           三模式之一 focus/peer/cross（可选，控制 oss-bin 子目录）
#
# 环境变量：
#   OSS_FUZZ_DIR: oss-fuzz 仓库路径（默认 /root/gyx/oss-fuzz）
#   DC_DRIVER_CREATE_DIR: driver_create 根目录（默认脚本父目录的父目录）
# ============================================================
set -e

# -------------------- 参数处理 --------------------
PROJECT="${1:?missing project}"
DC_ONLY_TARGET="${2:-}"
MODE="${3:-}"

OSS_FUZZ_HOME="${OSS_FUZZ_DIR:-/root/gyx/oss-fuzz}"
DC_ROOT="${DC_DRIVER_CREATE_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
SANITIZER="${DC_SANITIZER:-address}"
LOGS_DIR="$DC_ROOT/artifacts/logs"
# oss-bin 提取目录：output/<project>/oss-bin[cov]/[<mode>/]
if [ -n "$DC_COV" ]; then
    BIN_SUB="oss-bin-cov"
else
    BIN_SUB="oss-bin"
fi
if [ -n "$MODE" ]; then
    EXTRACT_DIR="$DC_ROOT/artifacts/output/$PROJECT/$BIN_SUB/$MODE"
else
    EXTRACT_DIR="$DC_ROOT/artifacts/output/$PROJECT/$BIN_SUB"
fi
OUTPUT_LOG="${LOGS_DIR}/${PROJECT}.log"

# -------------------- 环境准备 --------------------
if [ ! -d "$OSS_FUZZ_HOME/projects/$PROJECT" ]; then
    echo "[-] 错误：未找到项目目录 $OSS_FUZZ_HOME/projects/$PROJECT"
    echo "    请确保 Dockerfile、build.sh、*_crfuzzer.* 等文件已放入该目录。"
    exit 1
fi

cd "$OSS_FUZZ_HOME"
mkdir -p "$LOGS_DIR" "$EXTRACT_DIR"
# P0：清空当前 mode 的 EXTRACT_DIR + build/out/$PROJECT，防旧二进制残留被当本轮成功
# （轮次内掩盖错误、replay 恒成功、跨次拿旧二进制去 fuzz）。只清当前 mode 子目录，不连累别的模式。
# dc_only 模式只清当前 target 的旧二进制，保留整批 build 的其他产物。
if [ -n "$DC_ONLY_TARGET" ]; then
    rm -f "$EXTRACT_DIR/$DC_ONLY_TARGET"
else
    rm -rf "$EXTRACT_DIR"/*
fi
rm -rf "$OSS_FUZZ_HOME/build/out/$PROJECT"
# P2 #11：保留上一次 log，避免 replay 冲掉历史（pipeline 结束后能看到上一次完整 log）
if [ -f "$OUTPUT_LOG" ]; then
    mv "$OUTPUT_LOG" "${OUTPUT_LOG}.prev"
fi
: > "$OUTPUT_LOG"
echo "===== $(date) : 开始构建项目 ${PROJECT} (mode=${MODE:-flat}) =====" | tee -a "$OUTPUT_LOG"

# -------------------- 1. 构建镜像和 fuzzers --------------------
# 容器 --network=host 走 clash 代理（127.0.0.1:7890）：apt + git clone 都通。
# Docker config 的 proxies 已删（之前自动传代理进容器导致 apt 502）。
# helper.py 从环境变量读 http_proxy 传 --build-arg，容器 --network=host 能访问宿主机 clash。
echo "[+] 构建基础镜像..." | tee -a "$OUTPUT_LOG"
yes y | python3 infra/helper.py build_image "$PROJECT" >> "$OUTPUT_LOG" 2>&1
echo "[+] 编译 fuzzers（sanitizer: $SANITIZER）..." | tee -a "$OUTPUT_LOG"
DC_ONLY_ENV=()
if [ -n "$DC_ONLY_TARGET" ]; then
    echo "[+] DC_ONLY 单编模式：仅编译 $DC_ONLY_TARGET" | tee -a "$OUTPUT_LOG"
    DC_ONLY_ENV=(-e "DC_ONLY=$DC_ONLY_TARGET")
fi
yes y | python3 infra/helper.py build_fuzzers "${DC_ONLY_ENV[@]}" --sanitizer "$SANITIZER" "$PROJECT" >> "$OUTPUT_LOG" 2>&1

# -------------------- 2. 从构建输出目录提取自定义 fuzzer --------------------
OUT_DIR="$OSS_FUZZ_HOME/build/out/$PROJECT"
if [ ! -d "$OUT_DIR" ]; then
    echo "[-] 错误：构建输出目录不存在 $OUT_DIR" | tee -a "$OUTPUT_LOG"
    exit 1
fi

echo "[+] 正在从 $OUT_DIR 提取自定义 *_crfuzzer ..." | tee -a "$OUTPUT_LOG"
mkdir -p "$EXTRACT_DIR"

found=0
for f in "$OUT_DIR"/*_crfuzzer; do
    if [ -f "$f" ] && [ -x "$f" ]; then
        cp "$f" "$EXTRACT_DIR/"
        echo "    已提取: $(basename "$f")" | tee -a "$OUTPUT_LOG"
        found=1
    fi
done

if [ $found -eq 0 ]; then
    echo "[-] 警告：未找到任何 *_crfuzzer 文件，请检查构建日志。" | tee -a "$OUTPUT_LOG"
else
    echo "[+] 自定义 fuzzer 已提取至: $EXTRACT_DIR" | tee -a "$OUTPUT_LOG"
fi
