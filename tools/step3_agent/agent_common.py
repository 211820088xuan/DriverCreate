"""
driver_create/agent_common.py — 多 Agent 编译修复循环的公共底座

本模块为主 agent（agent_main）、分诊 agent（agent_triage）、编译修复 agent（agent_build_fix）
以及编排器（agent_pipeline）提供共享基础设施。采用手写 OpenAI 兼容 function-calling + 路径沙箱，
不引入第三方 agent 框架。

核心功能：
  - resolve_within                 多根路径沙箱（限定 agent 读写范围）
  - tool_read_file / tool_list_dir / tool_grep   双根探查工具
  - replace_or_append_marked_block / read_marked_block   标记块幂等写入/读取
  - backup_build_file / restore_build_file       .dcbak 备份与回滚
  - search_log                     构建 log 正则搜索（带上下文、总量截断）
  - run_agent_loop                 OpenAI 兼容 function-calling tool-loop 驱动
  - project_roots / deepseek_available   小工具

设计不变量：
  - 标记块幂等：重复注入替换块内内容，绝不重复追加
  - .dcbak 会话语义：backup_build_file 会话开始覆盖式刷新；标记块写入仅在缺失时补建，
    保证一次会话内多次写块仍保留"会话前快照"，可回滚
  - 沙箱：越界（含 .. / 符号链接逃逸，靠 Path.resolve() 归一后 relative_to 判定）返回 None
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional

import json

import requests as _req

from config import (
    SRC_DIR, OUTPUT_DIR, OSS_FUZZ_DIR,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_FAST_MODEL,
)


# ══════════════════════════════════════════════════════════════════════
# 标记块常量（Dockerfile 与 build.sh 同用 `#` 行注释）
# ══════════════════════════════════════════════════════════════════════

MARKER_BEGIN = "# >>> dc-injected >>>"
MARKER_END = "# <<< dc-injected <<<"

DCBAK_SUFFIX = ".dcbak"


# ══════════════════════════════════════════════════════════════════════
# 路径沙箱（泛化 agent_repair.py:_resolve_path 到多根）
# ══════════════════════════════════════════════════════════════════════

def resolve_within(path: str | Path, roots: Iterable[str | Path]) -> Optional[Path]:
    """把相对/绝对 path 解析为绝对 Path，且必须落在 roots 之一之内，否则返回 None。

    与 agent_repair._resolve_path 同构，只是把「两个硬编码根」泛化成任意根列表：
      - 相对路径：依次在每个 root 下试探，第一个存在的命中；都不存在则挂到第一个 root
        （便于「即将创建的文件」也能通过沙箱校验）。
      - 绝对路径：直接 resolve。
    关键安全点：先 Path.resolve() 归一（折叠 `..`、跟随符号链接），再 relative_to 判定，
    因此 `root/../../etc/passwd` 或指向根外的符号链接都会被拒。
    """
    root_paths = [Path(r).resolve() for r in roots]
    if not root_paths:
        return None

    p = Path(path)
    if p.is_absolute():
        p = p.resolve()
    else:
        resolved: Optional[Path] = None
        for r in root_paths:
            cand = (r / p).resolve()
            if cand.exists():
                resolved = cand
                break
        p = resolved if resolved is not None else (root_paths[0] / p).resolve()

    for r in root_paths:
        try:
            p.relative_to(r)
            return p
        except ValueError:
            continue
    return None


def project_roots(project: str) -> list[Path]:
    """主 agent / 编译修复 agent 探查项目文件时使用的双根：
    oss-fuzz/projects/<project>/（构建上下文） 与 SRC_DIR/<project>/（库源码）。"""
    return [OSS_FUZZ_DIR / "projects" / project, SRC_DIR / project]


# ══════════════════════════════════════════════════════════════════════
# 双根探查工具（read_file / list_dir / grep）
# ══════════════════════════════════════════════════════════════════════

def _rel_display(p: Path, roots: Iterable[str | Path]) -> str:
    """把绝对路径显示为相对某个根的短路径，便于工具输出可读。"""
    for r in roots:
        try:
            return str(p.relative_to(Path(r).resolve()))
        except ValueError:
            continue
    return str(p)


def tool_read_file(path: str, roots: Iterable[str | Path],
                   start_line: int = 1, max_lines: int = 200) -> str:
    """读文件片段（沙箱：path 必须落在 roots 之内）。格式对齐 agent_repair.tool_read_source。"""
    roots = list(roots)
    resolved = resolve_within(path, roots)
    if resolved is None:
        return f"[error] 路径 {path} 不在允许的根目录内"
    if not resolved.is_file():
        return f"[error] {resolved} 不是文件或不存在"
    try:
        content = resolved.read_text(errors="ignore")
    except OSError as e:
        return f"[error] 读文件失败: {e}"
    lines = content.splitlines()
    start = max(1, start_line)
    end = min(len(lines), start - 1 + max_lines)
    chunk = lines[start - 1:end]
    header = f"# {_rel_display(resolved, roots)} (lines {start}-{end} of {len(lines)})"
    body = "\n".join(f"{i + start:6d}  {ln}" for i, ln in enumerate(chunk))
    return f"{header}\n{body}"


def tool_list_dir(path: str, roots: Iterable[str | Path]) -> str:
    """列目录一层（沙箱）。目录用 '/' 结尾标记。"""
    roots = list(roots)
    resolved = resolve_within(path, roots)
    if resolved is None:
        return f"[error] 路径 {path} 不在允许的根目录内"
    if not resolved.is_dir():
        return f"[error] {resolved} 不是目录或不存在"
    entries = []
    for child in sorted(resolved.iterdir(), key=lambda c: (c.is_file(), c.name)):
        entries.append(child.name + ("/" if child.is_dir() else ""))
    if not entries:
        return f"[empty] {_rel_display(resolved, roots)} 为空"
    header = f"# {_rel_display(resolved, roots)} ({len(entries)} entries)"
    return header + "\n" + "\n".join(entries)


def tool_grep(pattern: str, roots: Iterable[str | Path],
              globs: Optional[list[str]] = None, max_results: int = 50) -> str:
    """在 roots（存在的那些）里正则搜索。优先 ripgrep，fallback grep。
    返回 'path:line:content' 形式命中，截断到 max_results。"""
    roots = [Path(r) for r in roots]
    search_dirs = [r for r in roots if r.is_dir()]
    if not search_dirs:
        return "[error] 没有可搜索的根目录（都不存在）"

    rg_cmd = ["rg", "-n", "--no-heading", "-S"]
    for g in (globs or []):
        rg_cmd += ["-g", g]
    rg_cmd += ["--", pattern] + [str(d) for d in search_dirs]
    res = None
    try:
        res = subprocess.run(rg_cmd, capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        res = None
    if res is None or res.returncode > 1:
        grep_cmd = ["grep", "-rnE"]
        for g in (globs or []):
            grep_cmd.append(f"--include={g}")
        grep_cmd += ["--", pattern] + [str(d) for d in search_dirs]
        try:
            res = subprocess.run(grep_cmd, capture_output=True, text=True, timeout=25)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return "[error] grep 失败或超时"

    lines = (res.stdout or "").splitlines()
    if not lines:
        return f"[no match] '{pattern}' 未命中"
    # 去掉每个根的绝对前缀，提高可读性
    prefixes = [str(d.resolve()) + os.sep for d in search_dirs]
    out = []
    for ln in lines[:max_results]:
        for pre in prefixes:
            if ln.startswith(pre):
                ln = ln[len(pre):]
                break
        out.append(ln[:300])
    extra = f"\n[truncated, {len(lines) - max_results} more]" if len(lines) > max_results else ""
    return "\n".join(out) + extra


# ══════════════════════════════════════════════════════════════════════
# `.dcbak` 备份 / 回滚
# ══════════════════════════════════════════════════════════════════════

def _dcbak_path(path: str | Path) -> Path:
    """<file> → <file>.dcbak（如 build.sh → build.sh.dcbak）。"""
    return Path(str(path) + DCBAK_SUFFIX)


def backup_build_file(path: str | Path, overwrite: bool = True) -> bool:
    """把 path 备份为 <path>.dcbak。

    overwrite=True（默认）：覆盖式刷新为当前磁盘内容——编排器在每次注入/修复**会话开始**时调，
      建立「会话前快照」。
    overwrite=False：仅当 .dcbak 不存在时才创建——供 replace_or_append_marked_block 内部调用，
      保证会话内多次写块不会把快照覆盖成「已注入版本」。
    path 不存在则无法备份，返回 False。
    """
    path = Path(path)
    bak = _dcbak_path(path)
    if not path.exists():
        return False
    if bak.exists() and not overwrite:
        return True
    shutil.copy2(path, bak)
    return True


def restore_build_file(path: str | Path) -> bool:
    """用 <path>.dcbak 覆盖回 path（回滚）。无备份则返回 False。"""
    path = Path(path)
    bak = _dcbak_path(path)
    if not bak.exists():
        return False
    shutil.copy2(bak, path)
    return True


# ══════════════════════════════════════════════════════════════════════
# 标记块：replace_or_append_marked_block / read_marked_block
# ══════════════════════════════════════════════════════════════════════

def _render_block(body: str) -> str:
    """渲染标记块（不含尾换行）。body 去掉首尾空行避免累积。"""
    body = (body or "").strip("\n")
    if body:
        return f"{MARKER_BEGIN}\n{body}\n{MARKER_END}"
    return f"{MARKER_BEGIN}\n{MARKER_END}"


def replace_or_append_marked_block(path: str | Path, new_body: str) -> bool:
    """把 new_body 写入 path 的 `# >>> dc-injected >>>` 标记块（幂等）。

    - 若已存在标记块 → 替换块内内容（不新增块）。
    - 否则 → 在文件末尾追加一个新块。
    - **绝不重复追加**：只要文件里已有一对标记，就走替换分支。
    - 写前确保 .dcbak 存在（overwrite=False，保留会话前快照）。

    返回 True（写成功）。
    """
    path = Path(path)
    # 强制前置：确保备份存在（不覆盖已有会话快照）
    backup_build_file(path, overwrite=False)

    original = path.read_text() if path.exists() else ""
    block = _render_block(new_body)

    begin_idx = original.find(MARKER_BEGIN)
    end_idx = original.find(MARKER_END)

    if begin_idx != -1 and end_idx != -1 and end_idx > begin_idx:
        # ── 替换：从 BEGIN 所在行首 到 END 所在行尾（含换行）整段替换 ──
        begin_line_start = original.rfind("\n", 0, begin_idx)
        begin_line_start = 0 if begin_line_start == -1 else begin_line_start + 1
        end_line_end = original.find("\n", end_idx)
        suffix = "" if end_line_end == -1 else original[end_line_end + 1:]
        prefix = original[:begin_line_start]
        new_content = prefix + block + "\n" + suffix
    else:
        # ── 追加：与原文之间空一行分隔 ──
        prefix = original
        if prefix and not prefix.endswith("\n"):
            prefix += "\n"
        new_content = (prefix + "\n" + block + "\n") if prefix else (block + "\n")

    if not new_content.endswith("\n"):
        new_content += "\n"
    path.write_text(new_content)
    return True


def read_marked_block(path: str | Path) -> Optional[str]:
    """读 path 当前的 dc-injected 标记块内容（不含两行标记）。无块返回 None。"""
    path = Path(path)
    if not path.exists():
        return None
    content = path.read_text(errors="ignore")
    b = content.find(MARKER_BEGIN)
    e = content.find(MARKER_END)
    if b == -1 or e == -1 or e < b:
        return None
    body_start = content.find("\n", b)
    if body_start == -1:
        return ""
    body_start += 1
    end_line_start = content.rfind("\n", 0, e)
    end_line_start = 0 if end_line_start == -1 else end_line_start + 1
    if end_line_start < body_start:
        return ""
    return content[body_start:end_line_start].rstrip("\n")


# ══════════════════════════════════════════════════════════════════════
# 构建 log 搜索（供分诊 agent；禁止整段读 log，只搜索 + 上下文）
# ══════════════════════════════════════════════════════════════════════

def search_log(log_path: str | Path, pattern: str, context_lines: int = 3,
               max_hits: int = 20, max_chars: int = 4000) -> str:
    """在 log_path 里正则搜索，返回命中行 + 前后 context_lines 行上下文，合并重叠窗口，
    总输出截断到 max_chars。命中数超过 max_hits 时截断并提示。"""
    log_path = Path(log_path)
    if not log_path.is_file():
        return f"[error] log 文件不存在: {log_path}"
    try:
        rx = re.compile(pattern)
    except re.error as e:
        return f"[error] 正则无效: {e}"
    try:
        lines = log_path.read_text(errors="ignore").splitlines()
    except OSError as e:
        return f"[error] 读 log 失败: {e}"

    hit_idxs = [i for i, ln in enumerate(lines) if rx.search(ln)]
    if not hit_idxs:
        return f"[no match] '{pattern}' 在 {log_path.name} 未命中"
    total_hits = len(hit_idxs)
    hit_idxs = hit_idxs[:max_hits]

    # 合并重叠 / 相邻的上下文窗口
    windows: list[list[int]] = []
    for i in hit_idxs:
        lo = max(0, i - context_lines)
        hi = min(len(lines), i + context_lines + 1)
        if windows and lo <= windows[-1][1]:
            windows[-1][1] = max(windows[-1][1], hi)
        else:
            windows.append([lo, hi])

    chunks: list[str] = []
    total = 0
    truncated = False
    for lo, hi in windows:
        seg = "\n".join(f"{i + 1:6d}  {lines[i]}" for i in range(lo, hi))
        if total + len(seg) > max_chars:
            remain = max_chars - total
            if remain > 0:
                chunks.append(seg[:remain])
            truncated = True
            break
        chunks.append(seg)
        total += len(seg) + 4  # 分隔符预算
    out = "\n  --\n".join(chunks)
    notes = []
    if total_hits > max_hits:
        notes.append(f"{total_hits} hits, only first {max_hits} shown")
    if truncated:
        notes.append(f"output capped at {max_chars} chars")
    if notes:
        out += "\n[truncated: " + "; ".join(notes) + "]"
    return out


# ══════════════════════════════════════════════════════════════════════
# 小工具
# ══════════════════════════════════════════════════════════════════════

def deepseek_available() -> bool:
    """是否具备调 DeepSeek 的凭证。无凭证时编排器优雅降级（跳过 LLM agent）。"""
    return bool(DEEPSEEK_API_KEY)


def to_openai_tools(tools: list[dict]) -> list[dict]:
    """把 {name, description, input_schema} 列表转成 OpenAI function-calling 格式。
    与 agent_repair._to_openai_tools 同构（纯转换，无 LLM）。"""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]


def clip(text: str, limit: int = 6000) -> str:
    """截断工具输出，防止上下文爆炸。"""
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[... clipped {len(text) - limit} chars ...]"


# ══════════════════════════════════════════════════════════════════════
# LLM 调用 + tool loop 驱动
# ══════════════════════════════════════════════════════════════════════
# 通用的 OpenAI 兼容 function-calling tool loop：
# requests 调 DeepSeek + 消息拼接 + finish_reason 处理 + tool result 截断（clip）。
# 各 agent（主注入 / 分诊 / 编译修复）把自己的 tools + 一个 handler(name,args)->str
# 传进来即可，不必各写一遍 loop。agent_repair.py 因带每-driver 编译预算等特殊逻辑，
# 保留其自身的 loop 实现。

class AgentResult:
    """tool loop 的收尾结果。

    submitted:   是否有某个工具把 done 置真（显式 submit / 终止工具）。
    payload:     该终止工具 handler 通过 ctx["submit"](obj) 交回的任意对象（如 routes / reason）。
    steps:       实际执行的 loop 轮数。
    stop_reason: 'submitted' | 'model_stop' | 'no_tool_calls' | 'max_steps' | 'api_error' | 'no_credentials'。
    """

    def __init__(self):
        self.submitted = False
        self.payload = None
        self.steps = 0
        self.stop_reason = ""

    def __repr__(self):
        return (f"AgentResult(submitted={self.submitted}, stop_reason={self.stop_reason!r}, "
                f"steps={self.steps}, payload={self.payload!r})")


def run_agent_loop(
    system_prompt: str,
    user_text: str,
    tools: list[dict],
    handler,
    *,
    model: Optional[str] = None,
    max_steps: int = 8,
    max_tokens: int = 16384,
    tool_result_limit: int = 6000,
    label: str = "agent",
    verbose: bool = True,
) -> AgentResult:
    """驱动一个多轮 function-calling tool loop（照 agent_repair.py 的循环写）。

    参数：
      system_prompt / user_text   两条初始消息。
      tools                        [{name, description, input_schema}]（本函数内部转 OpenAI 格式）。
      handler(name, args, ctx)->str
                                   工具分发回调，返回给模型的 tool result 字符串（本函数负责 clip）。
                                   ctx 提供：
                                     ctx["submit"](obj)  —— 标记终止并存 payload（终止型工具里调）。
                                     ctx["messages"]      —— 只读，便于 handler 需要时检视历史。
      model                        覆盖模型；默认 DEEPSEEK_MODEL / DEEPSEEK_FAST_MODEL。
      max_steps                    loop 上限。

    返回 AgentResult。无凭证 / 无模型时 stop_reason='no_credentials'，submitted=False（调用方降级）。
    """
    result = AgentResult()

    api_key = DEEPSEEK_API_KEY
    use_model = model or DEEPSEEK_MODEL or DEEPSEEK_FAST_MODEL
    if not api_key or not use_model:
        result.stop_reason = "no_credentials"
        return result

    base_url = (DEEPSEEK_BASE_URL or "https://api.deepseek.com").rstrip("/")
    url = base_url + "/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    openai_tools = to_openai_tools(tools)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_text},
    ]

    # 闭包：终止型工具通过 ctx["submit"] 交回 payload 并请求结束 loop
    _submit_flag = {"done": False}

    def _submit(obj: Any = None):
        result.submitted = True
        result.payload = obj
        _submit_flag["done"] = True

    ctx = {"submit": _submit, "messages": messages}

    for step in range(max_steps):
        result.steps = step + 1
        payload = {
            "model": use_model,
            "max_tokens": max_tokens,
            "messages": messages,
            "tools": openai_tools,
            "tool_choice": "auto",
        }
        try:
            resp = _req.post(url, json=payload, headers=headers, timeout=180)
            if resp.status_code != 200:
                if verbose:
                    print(f"    [{label}] step {step}: API HTTP {resp.status_code}: {resp.text[:200]}")
                result.stop_reason = "api_error"
                break
            resp_data = resp.json()
        except Exception as e:
            if verbose:
                print(f"    [{label}] step {step}: API 调用失败 {e}")
            result.stop_reason = "api_error"
            break

        choice = resp_data.get("choices", [{}])[0]
        msg = choice.get("message", {})
        finish_reason = choice.get("finish_reason", "")
        content_text = msg.get("content") or ""
        tool_calls_raw = msg.get("tool_calls") or []

        assistant_msg: dict[str, Any] = {"role": "assistant", "content": content_text or None}
        if tool_calls_raw:
            assistant_msg["tool_calls"] = tool_calls_raw
        messages.append(assistant_msg)

        if finish_reason == "stop" and not tool_calls_raw:
            if verbose:
                print(f"    [{label}] step {step}: 模型直接 stop 未 submit")
                if content_text:
                    print(f"            text: {content_text[:200]}")
            result.stop_reason = "model_stop"
            break

        if not tool_calls_raw:
            result.stop_reason = "no_tool_calls"
            break

        tool_result_msgs = []
        for tc in tool_calls_raw:
            tc_id = tc.get("id", "")
            func = tc.get("function", {})
            name = func.get("name", "")
            try:
                args = json.loads(func.get("arguments", "{}"))
            except (json.JSONDecodeError, TypeError):
                args = {}
            try:
                out = handler(name, args, ctx)
            except Exception as e:
                out = f"[error] tool {name} 异常: {e}"
            tool_result_msgs.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": clip(out if isinstance(out, str) else str(out), tool_result_limit),
            })

        messages.extend(tool_result_msgs)

        if _submit_flag["done"]:
            result.stop_reason = "submitted"
            break
    else:
        result.stop_reason = result.stop_reason or "max_steps"

    if not result.stop_reason:
        result.stop_reason = "max_steps"
    return result

