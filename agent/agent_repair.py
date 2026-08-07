"""
driver_create/agent_repair.py — 代码修复 Agent

通过 tool loop 修复 driver 源码层面的错误。相比一次性 prompt 修复，agent loop 能让 LLM：
  - 用 grep_symbol 验证符号是否真实存在
  - 用 read_source 读取项目头文件与其他 driver 样例代码
  - 用 list_drivers_dir 查看相邻 driver 作为参照
  - 用 compile_driver 写回源文件 + 试编译，根据编译反馈迭代修复

入口：agent_repair_driver(...) → 修复后源码 str 或 None（失败时由调用方 fallback）

工具：
  grep_symbol       在 SRC/<project> 里 grep 符号定义/调用
  read_source       读源码片段（含相对路径与绝对路径，做了越界保护）
  list_drivers_dir  列出该项目已有的 fuzz driver，给 agent 参考样本
  compile_driver    写回源文件 + 试编译（调用 replay_fn 重编）
  submit_fix        agent 显式终止，提交最终代码

控制：
  - max_steps 控制循环上限
  - no_improve_limit 控制错误数停滞次数
  - 必须开 prompt caching，否则 loop token 成本爆炸（system + tools 是大头）
  - agent 不能拿到 rm / 写 build 文件等危险操作，只能改 driver 源文件本身
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

import requests as _req

from config import (
    SRC_DIR, OUTPUT_DIR, INTERMEDIATE_DIR,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_FAST_MODEL,
    DC_MAX_COMPILE_STEPS_PER_DRIVER,
)


# ══════════════════════════════════════════════════════════════════════
# Tool schema (OpenAI function calling 格式)
# ══════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "grep_symbol",
        "description": (
            "查证符号是否真实存在（code/build 分诊的核心工具）。三态返回：\n"
            "  [sig_cache]  符号在 scored.json/fuzzing_headers.json 中 → 高置信度真实 → 漏链 → build\n"
            "  [grep]       符号在源码中找到（不在 sig_cache，可能是私有/未富化符号）→ 仍 build\n"
            "  [not_found]  既不在 sig_cache 也不在源码 → 疑似臆造 → code\n"
            "对每个 `undefined reference to X`，必须先 grep_symbol(X) 验证再决定 code/build。\n"
            "grep 兜底用 rg -w（词边界）+ 跳过注释行，避免 license 文本假阳性。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "符号名（函数/宏/类型/变量）"},
                "max_results": {"type": "integer", "default": 20},
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "read_source",
        "description": (
            "读源码文件片段。path 可以是相对路径（相对 SRC_DIR/<project>）或绝对路径，"
            "只允许读 SRC_DIR/<project> 或 OUTPUT_DIR/<project> 之内的文件。\n"
            "用途：看头文件确认 API 签名、看相邻 driver 学习写法。"
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
        "name": "list_drivers_dir",
        "description": (
            "列出该项目当前已生成的所有 fuzz driver（OUTPUT_DIR/<project>/*_fuzzer.{c,cpp}）。"
            "可以挑一个 read_source 来参考它怎么调 API、怎么处理输入。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "compile_driver",
        "description": (
            "把 code 写回当前 driver 的源文件，并用 build.log 中提取的 link 命令做精准重编"
            "（不跑全量 build.sh，单次几十秒到 3 分钟）。\n"
            "返回 {ok: bool, reason: str, error_tail: str}。每次调用都耗时，请节省。\n"
            "成功后建议立刻调 submit_fix 终止。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "完整修复后源码"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "submit_fix",
        "description": (
            "提交最终修复版本，结束 agent loop。\n"
            "什么时候调：(a) compile_driver 已经返回 ok=true；或 (b) 已经穷尽工具调查、"
            "确信当前 code 是最佳修复（即使没能在 loop 内编通过，也胜过再瞎改）。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "最终修复后的完整源码"},
                "reason": {"type": "string", "description": "一句话修复策略说明"},
            },
            "required": ["code"],
        },
    },
]


def _to_openai_tools(tools: list[dict]) -> list[dict]:
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

OPENAI_TOOLS = _to_openai_tools(TOOLS)


# ══════════════════════════════════════════════════════════════════════
# Tool implementations
# ══════════════════════════════════════════════════════════════════════

def _resolve_path(path: str, project: str) -> Optional[Path]:
    """把相对/绝对路径解析为绝对 Path，且必须落在 SRC_DIR/<project> 或 OUTPUT_DIR/<project> 之内。
    否则返回 None（agent 不准读项目外的文件）。"""
    src_root = (SRC_DIR / project).resolve()
    out_root = (OUTPUT_DIR / project).resolve()
    p = Path(path)
    if not p.is_absolute():
        # 优先在 src_root 下找，找不到再 out_root
        cand = (src_root / p).resolve()
        if cand.exists():
            p = cand
        else:
            p = (out_root / p).resolve()
    else:
        p = p.resolve()
    try:
        p.relative_to(src_root)
        return p
    except ValueError:
        pass
    try:
        p.relative_to(out_root)
        return p
    except ValueError:
        return None


def _load_signature_truth_set(project: str) -> set[str]:
    """从 scored.json + fuzzing_headers.json 加载已知真实符号集（sig_cache 主真值）。

    返回项目 API 名 + libFuzzer helper 函数/宏名的并集。命中 = 高置信度真实存在
    （scored.json 来自 step1 Q6 all_apis，含 KG 富化签名；fuzzing_headers.json 来自
    tools/analyze_fuzzing_headers.py 的 content_preview）。
    """
    truth: set[str] = set()

    # 1. scored.json 的 scored_apis[].api（项目全量 API，含富化签名）
    scored_path = INTERMEDIATE_DIR / project / "scored.json"
    if scored_path.is_file():
        try:
            data = json.loads(scored_path.read_text(encoding="utf-8"))
            for item in data.get("scored_apis", []) or []:
                api = item.get("api")
                if api:
                    truth.add(api)
        except (json.JSONDecodeError, OSError):
            pass

    # 2. fuzzing_headers.json 的 helper 函数/宏/类型（content_preview 提取）
    fh_path = INTERMEDIATE_DIR / project / "fuzzing_headers.json"
    if fh_path.is_file():
        try:
            fh = json.loads(fh_path.read_text(encoding="utf-8"))
            for h in fh.get("required_headers", []) + fh.get("optional_headers", []):
                content = h.get("content_preview", "") or ""
                if not content:
                    continue
                # 函数名：ident(  形式
                for m in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', content):
                    truth.add(m.group(1))
                # #define NAME
                for m in re.finditer(r'^[#\s]*define\s+([A-Za-z_]\w*)', content, re.MULTILINE):
                    truth.add(m.group(1))
                # typedef ... NAME;
                for m in re.finditer(r'^typedef\s+.*?\b([A-Za-z_]\w*)\s*;', content, re.MULTILINE | re.DOTALL):
                    truth.add(m.group(1))
        except (json.JSONDecodeError, OSError):
            pass

    return truth


_TRUTH_CACHE: dict[str, set[str]] = {}


def _get_truth_set(project: str) -> set[str]:
    """获取项目的真实符号集（进程内缓存，避免反复读盘）。"""
    if project not in _TRUTH_CACHE:
        _TRUTH_CACHE[project] = _load_signature_truth_set(project)
    return _TRUTH_CACHE[project]


def tool_grep_symbol(project: str, symbol: str, max_results: int = 20) -> str:
    """查证符号是否真实存在（code/build 分诊的核心工具，三态返回）。

    P0-3 修复：原实现用 rg -F（固定字符串、无词边界、不跳注释），license 文本里的符号名
    也命中，分诊 code/build 整体反向。现改为「签名缓存主真值 + grep -w 跳注释兜底」三态：

      [sig_cache]  符号在 scored.json/fuzzing_headers.json 中 → 高置信度真实 → kind=build（漏链）
      [grep]       符号在源码中找到（不在 sig_cache，可能是私有/未富化符号）→ 仍 build
      [not_found]  既不在 sig_cache 也不在源码 → 疑似臆造 → kind=code

    grep 兜底用 rg -w（C 标识符下划线是 word char，\b 在 _ 与非 \w 间有效，故 -w 能精确匹配
    整个标识符、不误中子串）+ 跳过纯注释行（// / * / /* 开头）。
    """
    if not symbol:
        return "[error] 空 symbol"

    # 1. sig_cache 主真值
    truth = _get_truth_set(project)
    if symbol in truth:
        return (f"[sig_cache] '{symbol}' 在 scored.json/fuzzing_headers.json 中记录为真实符号\n"
                f"  → 高置信度真实存在，疑似漏链 → kind=build")

    # 2. grep 源码兜底
    src_root = SRC_DIR / project
    if not src_root.is_dir():
        return (f"[not_found] '{symbol}' 既不在 sig_cache，SRC_DIR/{project} 也不存在"
                f" → 疑似臆造 → kind=code")

    # rg -w：词边界（C 标识符 _ 是 word char，故 \b 有效，能精确匹配整个标识符）
    cmd_rg = ["rg", "-n", "-w", "-F", "--no-heading", "-S",
              "-g", "*.c", "-g", "*.cc", "-g", "*.cpp", "-g", "*.h", "-g", "*.hpp",
              "--", symbol, str(src_root)]
    try:
        res = subprocess.run(cmd_rg, capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        res = None
    if res is None or res.returncode > 1:
        # fallback to grep -wn（同样用词边界）
        try:
            res = subprocess.run(
                ["grep", "-rwn", "--include=*.c", "--include=*.cpp", "--include=*.cc",
                 "--include=*.h", "--include=*.hpp", "--", symbol, str(src_root)],
                capture_output=True, text=True, timeout=20,
            )
        except subprocess.TimeoutExpired:
            return (f"[not_found] '{symbol}' grep 超时，sig_cache 也未命中"
                    f" → 疑似臆造 → kind=code")

    lines = (res.stdout or "").splitlines()
    if not lines:
        return (f"[not_found] '{symbol}' 既不在 sig_cache 也不在源码"
                f" → 疑似臆造 → kind=code")

    # 过滤纯注释行（降低假阳性：license 文本、注释提及的符号不算"定义"）
    filtered: list[str] = []
    for ln in lines:
        # rg -n 输出 "path:lineno:content"
        parts = ln.split(":", 2)
        if len(parts) < 3:
            continue
        content = parts[2].strip()
        if not content:
            continue
        # 跳过纯注释行
        if content.startswith("//") or content.startswith("/*") or content.startswith("*"):
            continue
        filtered.append(ln)
        if len(filtered) >= max_results:
            break

    if not filtered:
        return (f"[not_found] '{symbol}' 仅出现在注释/license 中（非定义）"
                f" → 疑似臆造 → kind=code\n"
                f"  （grep 命中 {len(lines)} 行但全是注释）")

    prefix = str(src_root) + os.sep
    out = []
    for ln in filtered:
        if ln.startswith(prefix):
            ln = ln[len(prefix):]
        out.append(ln[:300])
    extra = (f"\n[truncated, {len(lines) - len(filtered)} more]"
             if len(lines) > len(filtered) else "")
    return (f"[grep] '{symbol}' 在源码中找到（不在 sig_cache，可能是私有/未富化符号）"
            f" → 仍按真实处理 → kind=build\n"
            + "\n".join(out) + extra)


def tool_read_source(project: str, path: str, start_line: int = 1,
                     max_lines: int = 200) -> str:
    resolved = _resolve_path(path, project)
    if resolved is None:
        return f"[error] 路径 {path} 不在 SRC_DIR/{project} 或 OUTPUT_DIR/{project} 之内"
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
    header = f"# {resolved} (lines {start}-{end} of {len(lines)})"
    body = "\n".join(f"{i+start:6d}  {ln}" for i, ln in enumerate(chunk))
    return f"{header}\n{body}"


def tool_list_drivers_dir(project: str) -> str:
    out_dir = OUTPUT_DIR / project
    if not out_dir.is_dir():
        return f"[error] OUTPUT_DIR/{project} 不存在"
    drivers = []
    for ext in ("*.c", "*.cpp", "*.cc"):
        drivers.extend(sorted(out_dir.glob(ext)))
    if not drivers:
        return f"[empty] OUTPUT_DIR/{project} 下没有 driver 源文件"
    return "\n".join(str(d.relative_to(OUTPUT_DIR)) for d in drivers)


def tool_compile_driver(
    project: str,
    base: str,
    binary_name: str,
    source_path: Path,
    code: str,
    output_mirror_paths: list[Path],
    replay_fn,
) -> str:
    """写源文件 + 调 replay_fn 单 driver 重编。replay_fn 是 step3_build.try_replay_driver_build。"""
    try:
        source_path.write_text(code)
    except OSError as e:
        return json.dumps({"ok": False, "reason": f"写源文件失败: {e}", "error_tail": ""})
    for mirror in output_mirror_paths:
        try:
            mirror.write_text(code)
        except OSError:
            pass
    try:
        ok, reason = replay_fn(project, base, binary_name)
    except Exception as e:
        return json.dumps({"ok": False, "reason": f"replay 异常: {e}", "error_tail": ""})
    error_tail = ""
    if not ok and reason and "replay rc!=0" in reason:
        # reason 已经包含 stderr 末三行
        error_tail = reason
    return json.dumps({"ok": ok, "reason": reason, "error_tail": error_tail})


# ══════════════════════════════════════════════════════════════════════
# Agent loop
# ══════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """你是一个专业的 OSS-Fuzz fuzz driver 编译修复 agent，运行于开源软件自动化 fuzzing 研究流水线中。

**背景**：OSS-Fuzz 是 Google 主导的开源软件持续 fuzzing 平台，通过 coverage-guided fuzzing（libFuzzer / AFL++）配合 AddressSanitizer / UBSan 等 sanitizer，自动发现开源库中的 heap-buffer-overflow、use-after-free、stack-overflow、integer-overflow 等内存安全 bug 和未定义行为。每个 fuzz driver（也称 fuzz harness）是一个实现了 `LLVMFuzzerTestOneInput` 接口的 C/C++ 源文件，负责把 libFuzzer 提供的随机 byte payload 解析并喂给目标库的 API，从而驱动 fuzzer 探索目标库的代码路径。

你的任务：修复一个因编译/链接错误而无法构建的 fuzz driver 源文件，使其能在 OSS-Fuzz 的 Docker 构建环境（clang + ASan/fuzzer-no-link + LIB_FUZZING_ENGINE）中成功编译链接。

## 构建模型（注入式编译循环）

本项目采用**注入式编译循环**：driver 源码由流水线生成在 `output/<project>/`，stage 到 OSS-Fuzz
构建上下文后，由一段**注入到 build.sh 的编译循环**统一编译（遍历 `$SRC/*_fuzzer.<ext>`，复用原
项目 harness 的 include 路径与链接库，接 `$LIB_FUZZING_ENGINE`，输出 `$OUT/<stem>`）。特点：

- 编译脚手架（build.sh / Dockerfile 里注入的编译块、链接依赖）**不由你负责**——链接库、`-I`
  路径、`.a` 归档这类「编译/链接配置问题」由**编译修复 agent**处理。
- 分诊 agent 已判定：交给你的这个 driver 属**代码层错误**（错用 API、缺 include、类型不匹配、
  调用了项目里不存在的臆造符号等），根因在 driver 源码本身。
- **你只修 driver 源码**（`output/<project>/<file>`），绝不修改 build.sh / Dockerfile / 任何编译模板。

## 修复规则（按优先级排序）

### 链接错误
1. `undefined reference to 'X'`（X 是项目 API）：
   - `grep_symbol(X)` 验证该符号是否真实存在于项目源码中
   - 存在但被 `#ifdef` / `#if` 条件编译屏蔽 → 删除对 X 的调用及其依赖的逻辑块
   - 真不存在（库已移除或从未有该符号）→ 删除调用，替换为功能等价的现有 API（先 grep 找候选）
   - X 属于当前 target 未链接的模块 → 删除调用或换用已链接模块的等价 API

2. `multiple definition of 'X'`：把重复定义改为 `extern` 声明，或把定义移到 .c 文件中（若 driver 自己引入了重复定义）

### 编译错误
3. `implicit declaration of function 'X'` / `implicit function declaration`：
   - `grep_symbol(X)` 找到声明所在的头文件，在 driver 顶部加对应 `#include`
   - 若找不到任何头文件声明，则说明 API 不对外暴露，改用公共 API 替代

4. `incomplete type 'struct X'` / `no member named 'Y' in 'struct X'`：
   - 结构体是不透明类型（opaque），只能通过指针操作，不能栈分配也不能访问成员
   - 改用库提供的 `X_new()` / `X_create()` 工厂函数分配，`X_free()` / `X_destroy()` 释放
   - 无法访问成员的，改用对应的 getter/setter 函数

5. 类型不匹配 / `incompatible pointer type` / `passing argument N ... from incompatible pointer type`：
   - 插入显式类型转换 `(TargetType *)ptr`，或根据函数签名重新声明变量类型

6. `error: too many/few arguments to function 'X'`：对照签名（已在 user 消息中提供）修正参数个数

7. `error: use of undeclared identifier 'X'`：声明或 #include 对应头文件；若是宏/枚举缺失，grep 找正确名称

### 不变约束
- `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` 入口签名必须保持完整，不得删除或重命名
- 修复后的 driver 必须至少调用一个目标库的有意义 API（不得退化为空函数或直接 return 0）
- 不得引入新的内存泄漏（分配了就要在所有路径上释放）
- 不得调用 `exit()` / `abort()`（会终止 fuzzer 进程）
- **fuzzing_headers.json 白名单守护**：driver 顶部的 `#include "fuzz_utils.h"` 等 fuzzing helper 头文件由流水线生成，绝不可删除或改名；若编译报错"找不到该文件"，这是构建配置问题，保留 include，改用 `compile_driver` 验证

## 工作流

1. **诊断阶段**：仔细阅读 user 消息中的错误日志，逐条分类（链接错误 / 编译错误 / 警告升错误），确定修复优先级
2. **验证假设**：对 `undefined reference` 和 `implicit declaration` 类错误，必须先用 `grep_symbol` 确认符号的真实存在性，再决定修复策略——禁止凭记忆猜测
3. **查看上下文**：用 `read_source` 读相关头文件或邻近 driver 的正确用法；用 `list_drivers_dir` 找参考样本
4. **试编译迭代**：用 `compile_driver` 提交修复版本并看实际报错；根据新的 error_tail 继续迭代
5. **提交**：编译成功立即 `submit_fix`；达到 max_steps 或穷尽手段仍未成功时，`submit_fix` 提交当前最优版本

## 工具使用约束

- `grep_symbol`：不要重复 grep 同一符号
- `read_source`：单次读够（默认 200 行），避免来回翻同一文件；路径须在项目根目录内
- `compile_driver`：单次耗时 30s–3min，**每 driver 有独立预算**（通常 3 次），超限拒绝；只用来验证有把握的修复版本，不要试探性乱改。每次调用后 tool result 会返回 `compile_remaining` 剩余次数
- `list_drivers_dir`：查找参考 driver 时调用一次即可

## 终止条件

必须以 `submit_fix(code, reason)` 收尾。未调用 submit_fix 而 end_turn 视为 agent 失败，caller 将放弃该 driver。
"""


def _build_user_message(base: str, binary_name: str, source_code: str,
                         errors: list[str], unavailable_symbols: set[str],
                         compile_remaining: int = 3) -> str:
    err_text = "\n".join(errors[:25])
    budget_hint = f"\n\n**compile_driver 预算**: 本 driver 剩余 {compile_remaining} 次编译机会（每次耗时 30s–3min）。请在有把握时调用，避免试探性修改。" if compile_remaining > 0 else "\n\n**compile_driver 预算已耗尽**，无法再调用 compile_driver。请提交当前最优版本。"
    return f"""## 待修复 fuzz driver

- **base**: `{base}`
- **fuzzer binary**: `{binary_name}`

## 当前源码
```c
{source_code}
```

## 编译/链接错误日志（最多 25 条）
```
{err_text}
```
{budget_hint}

请按 [REDACTED] 中的工作流逐步修复上述错误，确保 fuzz driver 能在 OSS-Fuzz 构建环境（clang + ASan + LIB_FUZZING_ENGINE）中编译链接成功。"""


def _looks_like_driver(code: str) -> bool:
    return bool(code) and "LLVMFuzzerTestOneInput" in code and code.count("{") == code.count("}")


def agent_repair_driver(
    source_path: str | Path,
    binary_name: str,
    base: str,
    errors: list[str],
    project: str,
    unavailable_symbols: set[str],
    replay_fn,
    output_mirror_paths: Optional[list[Path]] = None,
    max_steps: int = 8,
    no_improve_limit: int = 3,
    model: Optional[str] = None,
    compile_budget: Optional[int] = None,
) -> Optional[str]:
    """Agent 化修复入口。返回修复后的代码或 None（失败）。

    参数：
      source_path           被修复 driver 的实际源路径（注入到 SRC 后的位置）
      binary_name           对应的二进制名（如 'json_tokener_parse_fuzzer'）
      base                  driver 基名（如 'json_tokener_parse'）
      errors                解析出来的该 driver 错误行（来自 parse_build_errors）
      project               OSS-Fuzz 项目名
      unavailable_symbols   全局不可用符号集合（来自 parse_build_errors 的 undef_symbols）
      replay_fn             step3_build.try_replay_driver_build 函数（依赖注入避免循环 import）
      output_mirror_paths   修复后还要镜像写到这些路径（OUTPUT 目录下的 *_fuzzer.{c,cpp}）
      max_steps             agent loop 最大轮数
      no_improve_limit      编译错误条数连续 K 次不下降则提前终止
      model                 覆盖 DEEPSEEK_MODEL
      compile_budget        每 driver 独立编译预算（None 时取 config.DC_MAX_COMPILE_STEPS_PER_DRIVER）
    """
    api_key = DEEPSEEK_API_KEY
    if not api_key:
        return None

    source_path = Path(source_path)
    if not source_path.exists():
        return None
    original_code = source_path.read_text()
    output_mirror_paths = output_mirror_paths or []

    base_url = (DEEPSEEK_BASE_URL or "https://api.deepseek.com").rstrip("/")
    url = base_url + "/chat/completions"
    use_model = model or DEEPSEEK_MODEL or DEEPSEEK_FAST_MODEL
    if not use_model:
        return None

    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    # Phase 4: compile_budget 硬计数（每 driver 独立预算）
    if compile_budget is None:
        compile_budget = DC_MAX_COMPILE_STEPS_PER_DRIVER
    compile_counter = [0]  # 可变 list，跨工具调用共享

    user_text = _build_user_message(base, binary_name, original_code,
                                     errors, unavailable_symbols, compile_budget)
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_text},
    ]

    last_err_count = len(errors)
    no_improve = 0
    final_code: Optional[str] = None
    submitted_reason = ""

    for step in range(max_steps):
        payload = {
            "model": use_model,
            "max_tokens": 16384,
            "messages": messages,
            "tools": OPENAI_TOOLS,
            "tool_choice": "auto",
        }
        try:
            resp = _req.post(url, json=payload, headers=headers, timeout=180)
            if resp.status_code != 200:
                print(f"    [agent] step {step}: API HTTP {resp.status_code}: {resp.text[:200]}")
                break
            resp_data = resp.json()
        except Exception as e:
            print(f"    [agent] step {step}: API 调用失败 {e}")
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
            print(f"    [agent] step {step}: 模型直接 stop 未 submit，放弃")
            print(f"            text: {content_text[:200]}")
            break

        if not tool_calls_raw:
            break

        tool_result_msgs = []
        terminated = False
        for tc in tool_calls_raw:
            tc_id = tc.get("id", "")
            func = tc.get("function", {})
            name = func.get("name", "")
            try:
                args = json.loads(func.get("arguments", "{}"))
            except json.JSONDecodeError:
                args = {}

            try:
                if name == "grep_symbol":
                    out = tool_grep_symbol(project, args.get("symbol", ""),
                                           int(args.get("max_results", 20)))
                elif name == "read_source":
                    out = tool_read_source(project, args.get("path", ""),
                                           int(args.get("start_line", 1)),
                                           int(args.get("max_lines", 200)))
                elif name == "list_drivers_dir":
                    out = tool_list_drivers_dir(project)
                elif name == "compile_driver":
                    code = args.get("code", "")
                    # Phase 4: 硬计数预算检查
                    if compile_counter[0] >= compile_budget:
                        out = json.dumps({
                            "ok": False,
                            "reason": f"compile_driver 预算已耗尽（{compile_budget}/{compile_budget}），无法再编译。请提交当前最优版本。",
                            "error_tail": "",
                        })
                    elif not _looks_like_driver(code):
                        out = json.dumps({
                            "ok": False,
                            "reason": "代码不像有效 driver（缺 LLVMFuzzerTestOneInput 或大括号不平衡）",
                            "error_tail": "",
                        })
                    else:
                        compile_counter[0] += 1
                        out = tool_compile_driver(
                            project, base, binary_name, source_path, code,
                            output_mirror_paths, replay_fn,
                        )
                        parsed = json.loads(out)
                        if parsed.get("ok"):
                            final_code = code
                        # 追加剩余预算提示到 tool result
                        remaining = compile_budget - compile_counter[0]
                        parsed["compile_remaining"] = remaining
                        out = json.dumps(parsed)
                elif name == "submit_fix":
                    code = args.get("code", "")
                    reason = args.get("reason", "")
                    if _looks_like_driver(code):
                        final_code = code
                        submitted_reason = reason
                    else:
                        submitted_reason = reason + " (submit code 无效，沿用上次编通过版本)"
                    out = json.dumps({"accepted": final_code is not None})
                    terminated = True
                else:
                    out = f"[error] 未知工具 {name}"
            except Exception as e:
                out = f"[error] tool {name} 异常: {e}"

            tool_result_msgs.append({
                "role": "tool",
                "tool_call_id": tc_id,
                "content": out,
            })

        messages.extend(tool_result_msgs)

        if terminated:
            break

        # 错误数停滞检测
        for tr in tool_result_msgs:
            try:
                data = json.loads(tr["content"])
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(data, dict) or "ok" not in data:
                continue
            tail = data.get("error_tail", "") or data.get("reason", "")
            new_err_count = tail.count("error:") if tail else (0 if data.get("ok") else last_err_count)
            if new_err_count >= last_err_count:
                no_improve += 1
            else:
                no_improve = 0
            last_err_count = new_err_count
            break
        if no_improve >= no_improve_limit:
            print(f"    [agent] step {step}: 错误数连续 {no_improve_limit} 次未减少，提前终止")
            break

    if final_code and _looks_like_driver(final_code):
        if submitted_reason:
            print(f"    [agent] 修复完成: {submitted_reason[:120]}")
        return final_code

    # 失败：恢复源文件
    try:
        source_path.write_text(original_code)
        for mirror in output_mirror_paths:
            if mirror.exists():
                mirror.write_text(original_code)
    except OSError:
        pass
    return None

