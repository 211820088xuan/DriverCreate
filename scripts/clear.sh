#!/bin/bash
# ============================================================
# clear.sh — 清理 driver_create 某个项目跑 run_pipeline 留下的缓存/注入痕迹
#
# 清理内容（一个项目一次跑会污染这些地方）：
#   1. oss-fuzz/projects/<p>/ 里 stage 进去的 driver 源码（*_crfuzzer.*）
#   2. oss-fuzz/projects/<p>/{build.sh,Dockerfile} 的注入标记块（用 .dcbak 还原）
#   3. driver_create/artifacts/{output,intermediate}/<p>/  生成物 & 中间态
#   4. oss-fuzz/{oss-bin,build/out,build/work}/<p>/          构建产物
#   5. oss-fuzz/logs/<p>.log                                 构建日志
#
# 用法：
#   ./clear.sh <project> [<project2> ...]   清理指定项目
#   ./clear.sh all                          清理所有在 output/ 下出现过的项目
#   ./clear.sh <project> --dry-run          只打印将删什么，不动手（强烈建议先跑）
#   ./clear.sh <project> --keep-output      保留 artifacts/output/<p>（LLM 生成的 driver 源码）
#   ./clear.sh <project> --keep-intermediate 保留 artifacts/intermediate/<p>（step1 情报缓存）
#
# 还原策略（与项目设计一致）：
#   - driver：优先按 artifacts/intermediate/<p>/staged_manifest.json 精确删；
#     无 manifest 时回落——只删 oss-fuzz git 里【未跟踪】的 *_crfuzzer.*，
#     绝不碰项目自带的 *_fuzzer.c（呼应 log.md「首轮 touch-none」教训）。
#   - build.sh/Dockerfile：用同目录 .dcbak 覆盖还原后删 .dcbak；无 .dcbak 则跳过并告警
#     （不臆测原版；如需彻底还原且 oss-fuzz 是 git 仓库，可事后 git checkout）。
# ============================================================
set -euo pipefail

# -------------------- 固定路径（对齐 config.py，勿改）--------------------
DRIVER_CREATE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OSS_FUZZ_DIR="/root/gyx/oss-fuzz"
OUTPUT_DIR="${DRIVER_CREATE_DIR}/artifacts/output"
INTERMEDIATE_DIR="${DRIVER_CREATE_DIR}/artifacts/intermediate"
PROJECTS_DIR="${OSS_FUZZ_DIR}/projects"

# -------------------- 参数解析 --------------------
DRY_RUN=0
KEEP_OUTPUT=0
KEEP_INTERMEDIATE=0
PROJECTS=()
for a in "$@"; do
    case "$a" in
        --dry-run)          DRY_RUN=1 ;;
        --keep-output)      KEEP_OUTPUT=1 ;;
        --keep-intermediate) KEEP_INTERMEDIATE=1 ;;
        --*) echo "[-] 未知参数: $a"; exit 1 ;;
        *)   PROJECTS+=("$a") ;;
    esac
done

if [ "${#PROJECTS[@]}" -eq 0 ]; then
    echo "用法: $0 <project> [<project2> ...] [--dry-run] [--keep-output] [--keep-intermediate]"
    echo "     $0 all [--dry-run]"
    exit 1
fi

# all → 展开成 output/ 下所有项目名
if [ "${PROJECTS[0]}" = "all" ]; then
    PROJECTS=()
    if [ -d "$OUTPUT_DIR" ]; then
        for d in "$OUTPUT_DIR"/*/; do
            [ -d "$d" ] && PROJECTS+=("$(basename "$d")")
        done
    fi
    if [ "${#PROJECTS[@]}" -eq 0 ]; then
        echo "[i] artifacts/output/ 下没有任何项目，无需清理。"
        exit 0
    fi
    echo "[i] all → 将清理: ${PROJECTS[*]}"
fi

# -------------------- 小工具 --------------------
# rm 包装：dry-run 只打印；真删加 -rf 并回显
_rm() {
    local target="$1"
    [ -e "$target" ] || return 0
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "    [dry-run] rm -rf $target"
    else
        rm -rf "$target"
        echo "    已删 $target"
    fi
}

# 判断 oss-fuzz 是不是 git 仓库（driver 回落删除时用 git 区分自带/注入）
_oss_is_git() {
    git -C "$OSS_FUZZ_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1
}

# -------------------- 单项目清理 --------------------
clean_one() {
    local p="$1"
    local pdir="${PROJECTS_DIR}/${p}"
    echo "============================================================"
    echo ">>> 清理项目: $p"
    echo "============================================================"

    # ---- 1. projects/<p>/ 里 stage 进来的 driver ----
    local manifest="${INTERMEDIATE_DIR}/${p}/staged_manifest.json"
    if [ -d "$pdir" ]; then
        if [ -f "$manifest" ]; then
            echo "  [driver] 按 manifest 精确删: $manifest"
            # 从 JSON 的 "staged" 数组里抠出文件名（不引第三方，用 grep/sed 提裸文件名）
            local names
            names=$(grep -oE '"[^"]+_crfuzzer\.[a-zA-Z]+"' "$manifest" | tr -d '"' || true)
            if [ -z "$names" ]; then
                echo "    [!] manifest 里没解析到 *_crfuzzer.* 条目，跳过（不猜删）。"
            fi
            while IFS= read -r n; do
                [ -n "$n" ] && _rm "${pdir}/${n}"
            done <<< "$names"
        else
            # 回落：无 manifest → 只删 git 未跟踪的 *_crfuzzer.*（绝不碰自带 fuzzer）
            echo "  [driver] 无 manifest，回落删「git 未跟踪的 *_crfuzzer.*」"
            if _oss_is_git; then
                local f base
                for f in "$pdir"/*_crfuzzer.*; do
                    [ -e "$f" ] || continue
                    base="projects/${p}/$(basename "$f")"
                    if git -C "$OSS_FUZZ_DIR" ls-files --error-unmatch "$base" >/dev/null 2>&1; then
                        echo "    [跳过] $base 是 git 跟踪文件（项目自带），不删。"
                    else
                        _rm "$f"
                    fi
                done
            else
                echo "    [!] oss-fuzz 非 git 仓库、又无 manifest，无法安全区分自带/注入 driver。"
                echo "        为防误删项目自带 fuzzer，跳过 driver 删除。请手工确认。"
            fi
        fi

        # ---- 2. build.sh / Dockerfile 用 .dcbak 还原 ----
        local bf
        for bf in build.sh Dockerfile; do
            local target="${pdir}/${bf}"
            local bak="${target}.dcbak"
            if [ -f "$bak" ]; then
                if [ "$DRY_RUN" -eq 1 ]; then
                    echo "    [dry-run] 用 $bak 还原 $target 并删 .dcbak"
                else
                    cp "$bak" "$target"
                    rm -f "$bak"
                    echo "    [build] 已用 .dcbak 还原 $bf 并删除备份"
                fi
            elif [ -f "$target" ] && grep -q "dc-injected" "$target" 2>/dev/null; then
                echo "    [build] ⚠️ $bf 含 dc 注入块但无 .dcbak 备份，未还原（不臆测原版）。"
                echo "            oss-fuzz 若为 git 仓库可手工: git -C $OSS_FUZZ_DIR checkout projects/${p}/${bf}"
            fi
        done
    else
        echo "  [i] $pdir 不存在，跳过 projects 侧清理。"
    fi

     # ---- 3. driver_create 侧生成物 / 中间态 ----
     if [ "$KEEP_OUTPUT" -eq 1 ]; then
         echo "  [output] --keep-output，保留 ${OUTPUT_DIR}/${p}/driver（源码），删 oss-bin（二进制）"
         _rm "${OUTPUT_DIR}/${p}/oss-bin"
     else
         echo "  [output] 删 ${OUTPUT_DIR}/${p}"
         _rm "${OUTPUT_DIR}/${p}"
     fi
     if [ "$KEEP_INTERMEDIATE" -eq 1 ]; then
         echo "  [intermediate] --keep-intermediate，保留 ${INTERMEDIATE_DIR}/${p}"
     else
         echo "  [intermediate] 删 ${INTERMEDIATE_DIR}/${p}"
         _rm "${INTERMEDIATE_DIR}/${p}"
     fi

     # ---- 4. oss-fuzz 侧构建产物 ----
     echo "  [build-out] 删 oss-fuzz 构建产物 / 日志"
     _rm "${OSS_FUZZ_DIR}/oss-bin/${p}"          # 兼容旧路径残留
     _rm "${OSS_FUZZ_DIR}/build/out/${p}"
     _rm "${OSS_FUZZ_DIR}/build/work/${p}"

     # ---- 5. 构建日志 ----
     _rm "${DRIVER_CREATE_DIR}/artifacts/logs/${p}.log"
     _rm "${OSS_FUZZ_DIR}/logs/${p}.log"          # 兼容旧路径残留

    echo "  ✅ $p 清理完成"
}

# -------------------- 主流程 --------------------
if [ "$DRY_RUN" -eq 1 ]; then
    echo "########## DRY-RUN 模式：只打印不删除 ##########"
fi
for p in "${PROJECTS[@]}"; do
    clean_one "$p"
done
echo "============================================================"
if [ "$DRY_RUN" -eq 1 ]; then
    echo "DRY-RUN 结束。确认无误后去掉 --dry-run 再跑一次真正清理。"
else
    echo "全部清理完成: ${PROJECTS[*]}"
fi
echo "============================================================"
