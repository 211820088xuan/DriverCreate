"""
driver_create/agent_build_fix.py — 编译修复 Agent

拿分诊判为 build 类的失败 target + 错误证据，修改注入到 build.sh / Dockerfile 的
`dc-injected` 标记块（链接库、include 路径、.a 归档路径等），不改 driver 源码、不改块外原文。

入口：agent_build_fix(project, build_routes, ctx=None) -> bool
  build_routes 来自分诊（kind=='build' 的 Route 列表）。返回是否成功提交修复。

可写范围：oss-fuzz/projects/<project>/{build.sh, Dockerfile} 的标记块内（沙箱 + 文件名白名单，
经 agent_main._guarded_block_write）。改前 .dcbak 备份由 replace_or_append_marked_block 保证。

无 DeepSeek 凭证时优雅降级（返回 False，不崩）。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

from config import OSS_FUZZ_DIR, SRC_DIR
import agent_common as ac
import agent_main


OSS_FUZZ_PROJECTS = OSS_FUZZ_DIR / "projects"


# ══════════════════════════════════════════════════════════════════════
# find_lib：在 SRC_DIR/<project> 下找 .a/.so 真实相对路径（确定性辅助）
# ══════════════════════════════════════════════════════════════════════

def find_lib(project: str, name: str, max_results: int = 20) -> str:
    """在 SRC_DIR/<project> 下找库归档/共享库的真实相对路径。
    name 可为 'xml2' / 'libxml2' / 'libxml2.a' / 'z' 等，模糊匹配 lib<name>.a / lib<name>.so / <name>。
    解决「.a 路径写错」「autotools 产物在 .libs/、cmake 在 build/」这类 build 错误。"""
    src_root = SRC_DIR / project
    if not src_root.is_dir():
        return f"[error] SRC_DIR/{project} 不存在"
    stem = name
    for pre in ("lib",):
        if stem.startswith(pre):
            stem = stem[len(pre):]
    for suf in (".a", ".so"):
        if stem.endswith(suf):
            stem = stem[: -len(suf)]

    wanted = {
        f"lib{stem}.a", f"lib{stem}.so", f"{stem}.a", f"{stem}.so", name,
    }
    hits: list[str] = []
    for root, dirs, files in os.walk(src_root):
        dirs[:] = [d for d in dirs if d != ".git"]
        for f in files:
            if f in wanted or (f.startswith(f"lib{stem}") and (f.endswith(".a") or ".so" in f)):
                rel = os.path.relpath(os.path.join(root, f), src_root)
                hits.append(rel)
                if len(hits) >= max_results:
                    break
        if len(hits) >= max_results:
            break
    if not hits:
        return f"[no match] 未在 SRC_DIR/{project} 找到 {name} 对应的 .a/.so"
    return "\n".join(sorted(hits))


# ══════════════════════════════════════════════════════════════════════
# tools
# ══════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_marked_block",
        "description": (
            "读 build.sh 或 Dockerfile 当前的 `# >>> dc-injected >>>` 标记块内容（我们注入的编译块）。"
            "修复前先读它，知道现在链了什么、include 了什么。file 传 'build.sh' 或 'Dockerfile'。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {"file": {"type": "string", "enum": ["build.sh", "Dockerfile"]}},
            "required": ["file"],
        },
    },
    {
        "name": "read_file",
        "description": (
            "读 oss-fuzz/projects/<project>/ 或 SRC_DIR/<project>/ 内的文件片段（沙箱）。"
            "用途：读**原 build.sh**（块外原始内容）看项目自带 harness 怎么编、链哪些库；读库源码。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "default": 1},
                "max_lines": {"type": "integer", "default": 200},
            },
            "required": ["path"],
        },
    },
    {
        "name": "grep",
        "description": (
            "在 oss-fuzz/projects/<project>/ + SRC_DIR/<project>/ 里正则搜索。"
            "用途：找原 harness 的编译/链接行（如 grep '\\$CC' 或 grep 'LIB_FUZZING_ENGINE'）、"
            "找某头文件在源码树的位置（补 -I）、找某库的链接项。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "globs": {"type": "array", "items": {"type": "string"}},
                "max_results": {"type": "integer", "default": 50},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "find_lib",
        "description": (
            "在 SRC_DIR/<project> 下找 .a/.so 的真实相对路径（解决库路径写错）。"
            "name 可为 'xml2'/'libxml2'/'libxml2.a'。autotools 产物常在 .libs/，cmake 在 build/。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
    },
    {
        "name": "write_marked_block",
        "description": (
            "把修正后的**完整编译块**写回 build.sh 或 Dockerfile 的 dc-injected 标记块（幂等替换，"
            "只改标记块内，块外原文不动，改前自动 .dcbak 备份）。body 是块内全部内容（不含标记行本身）。"
            "file 传 'build.sh' 或 'Dockerfile'。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "enum": ["build.sh", "Dockerfile"]},
                "body": {"type": "string", "description": "标记块内的完整内容"},
            },
            "required": ["file", "body"],
        },
    },
    {
        "name": "rebuild",
        "description": (
            "触发一次完整重建（get_oss_fuzzer.sh）验证修复，返回 {ok_targets, still_failed, error_tail}。"
            "耗时（数分钟），**有独立预算**（默认 2 次），超限拒绝。改完有把握再调，别试探。"
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "submit_fix",
        "description": (
            "结束编译修复，提交最终编译块。什么时候调：rebuild 已让目标编过；"
            "或已穷尽手段、确信当前编译块最优。reason 一句话说明改了什么。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
        },
    },
]


SYSTEM_PROMPT = """你是 OSS-Fuzz fuzz driver 流水线里的**编译修复 agent**。

背景：流水线把 LLM 生成的 fuzz driver（`$SRC/*_fuzzer.<ext>`）用一段**注入到 build.sh 的编译
循环**（包在 `# >>> dc-injected >>>` … `# <<< dc-injected <<<` 标记块里）编成 fuzzer 二进制。
分诊 agent 已判定：以下失败 target 属**编译/链接配置问题**（不是 driver 源码问题）。你的任务是
修好这个**注入的编译块**，让它们能编过。

## 硬约束（越界即错）

- **只改标记块内**（用 write_marked_block）。绝不改块外原始 build.sh，绝不改 driver 源码
  （那是代码修复 agent 的活）。
- 保留原 harness 已验证的 include/链接项作为参照：先 read_file 原 build.sh / grep 原 harness 的
  `$CC ... $LIB_FUZZING_ENGINE` 编译行，照抄它的 -I 路径和链接库，再在编译循环里复用。
- 你能写的文件只有 build.sh 和 Dockerfile 的标记块。

## 修复规则（按错误类型）

- `cannot find -lXXX` → 找正确库名或 .a 路径：find_lib('XXX') 定位真实产物；或 grep 原 build.sh
  看项目自带 harness 链的是什么。补 `-lXXX` 或改成 .a 的相对/绝对路径。
- `undefined reference to 'X'`（分诊已确认 X 真实存在）→ 漏链某个库/对象。find_lib / grep 找到 X
  所在库，在链接项里补上。
- `fatal error: xxx.h: No such file`（该头项目里真实存在）→ 补 `-I<正确 include 目录>`
  （grep 该头在源码树的位置，取其目录）。
- `.a` 路径不存在 → find_lib 定位真实产物路径（autotools 常在 `.libs/`，cmake 在 `build/`）。

## 工作流

1. read_marked_block('build.sh') 看当前注入的编译块。
2. 针对每条 build 错误：find_lib / grep / read_file 原 harness，定位正确的库/头路径。
3. write_marked_block 写回修正后的**完整编译块**（保持单 driver 失败容错的 if/else 结构）。
4. （可选，预算有限）rebuild 验证；编过就 submit_fix。
5. 收尾必须 submit_fix(reason)。

编译循环必须保持对单个 driver 失败**容错**（`if $CC ...; then ... else WARNING; fi`），
保证整体 build.sh 退出 0，别让一个 driver 失败中断所有构建。"""


# ══════════════════════════════════════════════════════════════════════
# handler + 入口
# ══════════════════════════════════════════════════════════════════════

def _build_user_message(project: str, build_routes: list[dict]) -> str:
    lines = []
    for r in build_routes:
        ev = "\n".join(f"    {e}" for e in (r.get("evidence") or [])[:5])
        lines.append(f"- **{r.get('target')}**: {r.get('reason', '')}\n{ev}".rstrip())
    routes_txt = "\n".join(lines)
    return f"""## 编译修复任务

- **项目**: `{project}`
- 可写：`oss-fuzz/projects/{project}/build.sh` 和 `Dockerfile` 的 dc-injected 标记块（仅块内）。

## 分诊判为 build 类的失败 target 及证据
{routes_txt}

请按 system 的工作流：先 read_marked_block('build.sh') 看当前编译块，read_file 原 build.sh /
grep 原 harness 的编译行作参照，用 find_lib 定位正确的库/头路径，再 write_marked_block 写回
修正后的完整编译块，最后 submit_fix。只改标记块内，不碰块外原文与 driver 源码。"""


def _make_handler(project: str, mode: Optional[str] = None):
    roots = ac.project_roots(project)
    rebuild_budget = [2]           # 独立 rebuild 预算
    rebuild_count = [0]

    def handler(name: str, args: dict, ctx: dict) -> str:
        if name == "read_marked_block":
            fname = args.get("file", "build.sh")
            if fname not in agent_main.INJECTABLE_FILES:
                return f"[error] 只能读 {sorted(agent_main.INJECTABLE_FILES)}"
            path = OSS_FUZZ_PROJECTS / project / fname
            body = ac.read_marked_block(path)
            if body is None:
                return f"[info] {fname} 当前没有 dc-injected 标记块（可能主 agent 尚未注入）"
            return body or "[empty] 标记块为空"

        if name == "read_file":
            return ac.tool_read_file(args.get("path", ""), roots,
                                      int(args.get("start_line", 1)),
                                      int(args.get("max_lines", 200)))
        if name == "grep":
            return ac.tool_grep(args.get("pattern", ""), roots,
                                args.get("globs"), int(args.get("max_results", 50)))
        if name == "find_lib":
            return find_lib(project, args.get("name", ""))

        if name == "write_marked_block":
            fname = args.get("file", "build.sh")
            body = args.get("body", "")
            return agent_main._guarded_block_write(project, fname, body)

        if name == "rebuild":
            if rebuild_count[0] >= rebuild_budget[0]:
                return json.dumps({
                    "error": f"rebuild 预算已耗尽（{rebuild_budget[0]}/{rebuild_budget[0]}），"
                             f"请 submit_fix 提交当前编译块",
                }, ensure_ascii=False)
            rebuild_count[0] += 1
            try:
                agent_main.restage_drivers(project, mode)
            except Exception as e:
                return json.dumps({"error": f"restage 失败: {e}"}, ensure_ascii=False)
            log_path = agent_main.agent_main_build(project, timeout=1800, mode=mode)
            built, failed = agent_main.diff_products(project, mode)
            tail = ""
            if Path(log_path).is_file():
                try:
                    tail = "\n".join(Path(log_path).read_text(errors="ignore")
                                     .splitlines()[-20:])
                except OSError:
                    tail = ""
            return json.dumps({
                "ok_targets": sorted(built), "still_failed": sorted(failed),
                "rebuild_remaining": rebuild_budget[0] - rebuild_count[0],
                "error_tail": ac.clip(tail, 1500),
            }, ensure_ascii=False)

        if name == "submit_fix":
            # P2 #9：提交前 build.sh 语法自验，改坏则回滚 .dcbak 拒提交
            bsh = OSS_FUZZ_PROJECTS / project / "build.sh"
            if bsh.exists():
                import subprocess
                rc = subprocess.run(["bash", "-n", str(bsh)],
                                    capture_output=True, text=True).returncode
                if rc != 0:
                    # 语法错：回滚到 .dcbak
                    bak = bsh.with_suffix(bsh.suffix + ".dcbak")
                    if bak.exists():
                        import shutil
                        shutil.copy(str(bak), str(bsh))
                        return json.dumps({"error": "build.sh 语法错误，已回滚 .dcbak，请重新修复"}, ensure_ascii=False)
                    return json.dumps({"error": "build.sh 语法错误且无 .dcbak 可回滚"}, ensure_ascii=False)
            ctx["submit"]({"reason": args.get("reason", "")})
            return json.dumps({"accepted": True}, ensure_ascii=False)

        return f"[error] 未知工具 {name}"

    return handler


def agent_build_fix(project: str, build_routes: list[dict],
                    ctx: Optional[dict] = None,
                    max_steps: int = 10, model: Optional[str] = None) -> bool:
    """编译修复入口。改 build.sh/Dockerfile 的 dc-injected 标记块。

    mode 从 ctx["mode"] 取，透传给 _make_handler 内的 restage/diff。
    无凭证 → 优雅降级返回 False（不崩，编排器据此跳过）。
    成功提交 submit_fix → True。
    """
    if not build_routes:
        return False
    if not ac.deepseek_available():
        print("  [build_fix] 无 DeepSeek 凭证，跳过编译修复（降级）")
        return False

    mode = (ctx or {}).get("mode")

    # 会话开始：对可注入文件建 .dcbak 会话前快照（会话内多次写块保留此快照，可回滚）
    agent_main.session_backup_injectables(project)

    handler = _make_handler(project, mode)
    user_text = _build_user_message(project, build_routes)
    res = ac.run_agent_loop(
        SYSTEM_PROMPT, user_text, TOOLS, handler,
        model=model, max_steps=max_steps, label="build_fix",
    )
    if res.submitted:
        reason = (res.payload or {}).get("reason", "") if isinstance(res.payload, dict) else ""
        print(f"  [build_fix] 提交编译块修复: {reason[:120]}")
        return True
    print(f"  [build_fix] 未正常提交（{res.stop_reason}）")
    return False


# ══════════════════════════════════════════════════════════════════════
# CLI（调试）
# ══════════════════════════════════════════════════════════════════════

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m agent.agent_build_fix <project> [--mode=focus|peer|cross]")
        sys.exit(1)
    project = sys.argv[1]
    mode = None
    for a in sys.argv[2:]:
        if a.startswith("--mode="):
            mode = a.split("=", 1)[1]
    # 从 triage[_<mode>].json 读 build 类 route
    from config import intermediate_for
    triage_file = f"triage_{mode}.json" if mode else "triage.json"
    tj = intermediate_for(project) / triage_file
    routes = []
    if tj.exists():
        routes = [r for r in json.loads(tj.read_text()) if r.get("kind") == "build"]
    print(f"[build_fix] {project}[{mode or 'legacy'}]: {len(routes)} 个 build route")
    ctx = {"mode": mode}
    ok = agent_build_fix(project, routes, ctx)
    print(f"[build_fix] result: {ok}")


if __name__ == "__main__":
    main()
