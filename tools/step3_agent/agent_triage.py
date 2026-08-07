"""
driver_create/agent_triage.py — 分诊 Agent

读构建 log（用搜索，不整段读），对每个失败的 driver 判定错误类型：
  - code  → 代码修复 agent（agent_repair）：错误出在 driver 源文件本身
  - build → 编译修复 agent（agent_build_fix）：错误出在注入的编译命令或链接配置

入口：agent_triage(project, log_path, failed_targets) -> list[Route]
  Route = {"target": <stem>, "kind": "code"|"build", "evidence": [str], "reason": str}

核心判据：undefined reference to 'X' 一律先 grep_symbol(X) 验证符号真实性再归类——
真实符号漏链 → build；臆造符号 → code。不看符号名字面。

无 DeepSeek 凭证时自动回落 triage_deterministic（确定性分诊，仍能正确区分真/臆造符号）。
分诊结果存档 intermediate/<project>/triage.json 并返回。
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from config import intermediate_for
from tools.step3_agent import agent_common as ac
# 复用 agent_repair 的符号搜索 / 读源码
from tools.step3_agent.agent_repair import tool_grep_symbol, tool_read_source


# ══════════════════════════════════════════════════════════════════════
# 确定性判据核心（可离线单测；LLM 分诊也以它为准绳/兜底）
# ══════════════════════════════════════════════════════════════════════

# undefined reference 行里抽符号：`undefined reference to \`xmlReadMemory'`
_UNDEF_RE = re.compile(r"undefined reference to [`'\"]?([A-Za-z_]\w*)")
# `cannot find -lxml2`
_CANNOT_FIND_LIB_RE = re.compile(r"cannot find -l(\S+)")
# `fatal error: xxx.h: No such file`
_MISSING_HEADER_RE = re.compile(r"fatal error:\s*([^\s:]+\.h(?:pp)?)\s*:\s*No such file")


def symbol_exists_in_project(project: str, symbol: str) -> bool:
    """符号是否真实存在于项目（sig_cache 或源码）。复用 agent_repair.tool_grep_symbol。

    P0-3 三态返回适配：[sig_cache]/[grep] → True（真实）；[not_found]/[error] → False（臆造）。
    """
    if not symbol:
        return False
    out = tool_grep_symbol(project, symbol, max_results=5)
    # 三态：sig_cache / grep = 真实；not_found / error = 臆造
    if out.startswith("[sig_cache]") or out.startswith("[grep]"):
        return True
    return False


def classify_undefined_reference(project: str, symbol: str) -> tuple[str, str]:
    """对 undefined reference to symbol 判定 kind（核心分诊判据）。

    - grep 命中（符号真实存在于项目库）→ ("build", 真实库符号，注入编译块漏链)
    - grep 未命中（项目中查无此符号，疑似 LLM 臆造）→ ("code", 疑似臆造 API，需换真实 API)

    返回 (kind, reason)。这是「真符号漏链→build / 臆造符号→code」两个验收用例的判定函数。
    """
    if symbol_exists_in_project(project, symbol):
        return "build", (f"`{symbol}` 是项目中真实存在的库符号，"
                         f"注入的编译块漏链其所在库（补 -l/.a 即可）")
    return "code", (f"项目源码中查无符号 `{symbol}`，疑似 driver 臆造的 API，"
                    f"需在 driver 里换用真实存在的 API")


def classify_target_errors(project: str, target: str, error_lines: list[str]) -> Optional[dict]:
    """对单个失败 target 的错误行做确定性分诊，返回 Route（或 None 表示无可判据）。

    判据优先级：
      1. undefined reference → 先 grep_symbol 验证（唯一必须验证的一类）。
         任一真符号漏链 → build；否则（全是臆造符号）→ code。
      2. cannot find -lXXX / 库归档 No such file → build（缺链接库）。
      3. fatal error: xxx.h: No such file → 该头在项目源码里真实存在则 build（缺 -I），
         否则 code（driver include 了不存在的头）。
      4. clang `error:`（语法/类型/参数/未声明标识符等）→ code。
      5. 判不准 → 默认 code（driver agent 兜底能力更强）。

    这是 LLM 不可用时编排器可直接调用的确定性分诊，也是 LLM 分诊的锚点。
    """
    evidence: list[str] = []
    undef_symbols: list[str] = []
    for ln in error_lines:
        m = _UNDEF_RE.search(ln)
        if m:
            undef_symbols.append(m.group(1))
            evidence.append(ln.strip()[:300])

    # 1. undefined reference：必须 grep 验证
    if undef_symbols:
        real_missing = []
        fake = []
        for sym in dict.fromkeys(undef_symbols):  # 去重保序
            kind, _ = classify_undefined_reference(project, sym)
            (real_missing if kind == "build" else fake).append(sym)
        if real_missing:
            hits = "; ".join(
                tool_grep_symbol(project, s, max_results=2).splitlines()[0]
                for s in real_missing[:3]
            )
            return {
                "target": target,
                "kind": "build",
                "evidence": evidence[:8],
                "reason": (f"真实库符号漏链: {', '.join('`'+s+'`' for s in real_missing)}"
                           f"（grep 命中: {hits[:200]}）"),
            }
        return {
            "target": target,
            "kind": "code",
            "evidence": evidence[:8],
            "reason": (f"项目中不存在的符号，疑似 driver 臆造的 API: "
                       f"{', '.join('`'+s+'`' for s in fake)}，需换用真实 API"),
        }

    # 2. cannot find -lXXX
    for ln in error_lines:
        m = _CANNOT_FIND_LIB_RE.search(ln)
        if m:
            return {
                "target": target, "kind": "build",
                "evidence": [ln.strip()[:300]],
                "reason": f"缺链接库 -l{m.group(1)}，注入编译块需补正确库名/.a 路径",
            }

    # 3. fatal error: xxx.h: No such file
    for ln in error_lines:
        m = _MISSING_HEADER_RE.search(ln)
        if m:
            header = m.group(1)
            base = header.split("/")[-1]
            exists = symbol_exists_in_project(project, base)
            if exists:
                return {
                    "target": target, "kind": "build",
                    "evidence": [ln.strip()[:300]],
                    "reason": f"头文件 {header} 在项目源码里真实存在，注入编译块缺 -I 路径",
                }
            return {
                "target": target, "kind": "code",
                "evidence": [ln.strip()[:300]],
                "reason": f"driver include 的头 {header} 项目里不存在，需改 driver 的 #include",
            }

    # 4. clang error: → code
    code_err = [ln.strip()[:300] for ln in error_lines if "error:" in ln.lower()]
    if code_err:
        return {
            "target": target, "kind": "code",
            "evidence": code_err[:8],
            "reason": "driver 源码存在编译错误（语法/类型/参数/未声明标识符等）",
        }

    # 5. 判不准 → 默认 code
    if error_lines:
        return {
            "target": target, "kind": "code",
            "evidence": [l.strip()[:300] for l in error_lines[:5]],
            "reason": "错误类型判不准，默认归 code（driver agent 兜底能力更强）",
        }
    return None


def extract_target_error_lines(log_text: str, target: str) -> list[str]:
    """从 log 里抽取与某 target 相关的错误行（供确定性分诊/降级用）。

    以 target/源名出现处进入 scope，收集 error / undefined / fatal / no such file 行。
    遇到下一个 "Building XXX" 行（编译循环的下一个 target 块）退出 scope，
    防止 in_scope 永不复位导致后续 target 的 error 被误归给当前 target。
    """
    hits: list[str] = []
    in_scope = False
    stems = {target, target + ".c", target + ".cc", target + ".cpp", target + ".cxx"}
    for line in log_text.splitlines():
        low = line.lower()
        # 遇到 "Building XXX" 行：若含当前 target 则进入 scope，否则退出 scope
        if low.startswith("building "):
            in_scope = any(s in line for s in stems)
            continue
        if any(s in line for s in stems):
            in_scope = True
        if in_scope and ("error" in low or "undefined reference" in low
                         or "fatal error" in low or "no such file" in low
                         or "cannot find -l" in low):
            hits.append(line.strip()[:300])
    return hits[:25]


def triage_deterministic(project: str, log_path: str | Path,
                         failed_targets: list[str],
                         mode: Optional[str] = None) -> list[dict]:
    """不依赖 LLM 的确定性分诊（无凭证时编排器直接用它；也是 LLM 分诊的兜底/对照）。

    mode 当前不参与确定性分诊逻辑（grep_symbol/symbol_exists_in_project 是 mode-agnostic 的），
    保留参数为 API 一致性与未来按 mode 过滤 target 留口子。
    """
    log_path = Path(log_path)
    log_text = log_path.read_text(errors="ignore") if log_path.is_file() else ""
    routes: list[dict] = []
    for target in failed_targets:
        err_lines = extract_target_error_lines(log_text, target)
        route = classify_target_errors(project, target, err_lines)
        if route is None:
            route = {
                "target": target, "kind": "code", "evidence": [],
                "reason": "log 中未找到该 target 的错误行，默认归 code 待人工/agent 复核",
            }
        routes.append(route)
    return routes


# ══════════════════════════════════════════════════════════════════════
# 分诊 agent 的 tools（LLM 版；search_log/grep_symbol/read_source/submit_routes）
# ══════════════════════════════════════════════════════════════════════

TOOLS: list[dict[str, Any]] = [
    {
        "name": "search_log",
        "description": (
            "在构建 log 里正则搜索，返回命中行 + 前后上下文（总量截断）。"
            "必须用搜索定位每个失败 target 的错误行，不要假设能整段读 log。\n"
            "典型：search_log('undefined reference')、search_log('<target>')、"
            "search_log('cannot find -l')、search_log('fatal error')。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "正则"},
                "context_lines": {"type": "integer", "default": 3},
                "max_hits": {"type": "integer", "default": 20},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "grep_symbol",
        "description": (
            "查证符号是否真实存在（code/build 分野的核心工具）。三态返回：\n"
            "  [sig_cache]  符号在 scored.json/fuzzing_headers.json 中 → 高置信度真实 → kind=build（漏链）\n"
            "  [grep]       符号在源码中找到（不在 sig_cache，可能是私有/未富化符号）→ 仍 kind=build\n"
            "  [not_found]  既不在 sig_cache 也不在源码 → 疑似 driver 臆造 → kind=code\n"
            "对每个 `undefined reference to X`，必须先 grep_symbol(X) 验证再决定 code/build。\n"
            "禁止凭符号名字面猜测。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string"},
                "max_results": {"type": "integer", "default": 20},
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "read_source",
        "description": (
            "读 driver 源码或库头文件片段（沙箱：SRC_DIR/<project> 或 OUTPUT_DIR/<project> 之内）。"
            "用于确认某报错到底出在 driver 源码还是库配置。"
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
        "name": "submit_routes",
        "description": (
            "提交分诊结果数组，结束分诊。每个元素："
            "{target, kind: 'code'|'build', evidence: [关键错误行], reason: 一句话依据}。"
            "只对传入的失败 target 分诊，不要发明新 target。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "routes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "kind": {"type": "string", "enum": ["code", "build"]},
                            "evidence": {"type": "array", "items": {"type": "string"}},
                            "reason": {"type": "string"},
                        },
                        "required": ["target", "kind"],
                    },
                },
            },
            "required": ["routes"],
        },
    },
]


SYSTEM_PROMPT = """你是 OSS-Fuzz fuzz driver 自动化流水线里的**构建错误分诊 agent**。

背景：流水线把 LLM 生成的 fuzz driver（实现 `LLVMFuzzerTestOneInput` 的 C/C++ 测试桩）注入
OSS-Fuzz 项目，用注入到 build.sh 的编译循环把每个 driver 编成 fuzzer 二进制。部分 driver 编译
失败，你要读构建 log，为**每个失败 target** 判定错误归属，分发给下游两个修复 agent 之一：

- **code**（→ 代码修复 agent，改 driver 源码本身）。典型：
  - clang 在 `<target>.c` 上报 `error:`（语法、类型不匹配、参数个数不符、use of undeclared identifier）
  - `unknown type name` / `implicit declaration of function`
  - `undefined reference to 'X'` 且 grep_symbol(X) 在项目源码里**查无此符号** → driver 臆造的 API
  - driver `#include` 了项目里根本不存在的头
- **build**（→ 编译修复 agent，改我们注入到 build.sh/Dockerfile 的编译块）。典型：
  - `cannot find -lXXX`（缺链接库）
  - `fatal error: xxx.h: No such file` 且该头在项目源码里**真实存在**（缺 -I include 路径）
  - `undefined reference to 'X'` 且 grep_symbol(X) 证明 X 在项目库里**真实存在** → 漏链对应 .a/-l
  - 库归档 `.a` 路径不对（No such file 指向库文件）、Dockerfile COPY 相关错误

## 铁律（分诊正确性的核心）

1. **每个 `undefined reference to 'X'` 都必须先 grep_symbol(X) 验证**，再决定 code/build：
   - grep 命中真实定义 → **build**（真符号漏链）
   - grep 查无此符号 → **code**（臆造 API）
   同样是 undefined reference，判定**完全取决于 grep 结果，不看符号名字面**。
2. 用 **search_log 搜索**定位错误，不要假设能整段读 log。先 search_log 出每个 target 的报错，
   再对 undefined reference 逐个 grep_symbol。
3. 判不准时默认归 **code**（driver agent 兜底能力更强），并在 reason 写明依据。
4. 只对传入的失败 target 分诊；evidence 放最能说明问题的 1–3 行原始 log；reason 一句话。

## 工作流（批量优先，减少步数消耗）

1. **批量收集错误**：
   - 先用 search_log('undefined reference') 一次性拿到所有 undefined reference 错误
   - 再用 search_log('error:') 拿到所有代码编译错误
   - 必要时针对个别 target 用 search_log('<target>') 补充
2. **批量验证符号**：
   - 从第 1 步的结果中提取所有唯一符号（去重）
   - 对每个唯一符号调用一次 grep_symbol 验证真实性
   - 真符号 → kind=build；臆造符号 → kind=code
3. **组织分诊结果**：
   - 按 target 汇总错误和判定
   - 每个 target 一个 route：{target, kind, evidence, reason}
4. **提交**：submit_routes(routes) 提交全部结果

**关键**：先批量搜索/验证，再按 target 组织结果，避免逐个 target 线性处理导致步数爆炸。
必须以 submit_routes 收尾。"""


# ══════════════════════════════════════════════════════════════════════
# 入口：agent_triage
# ══════════════════════════════════════════════════════════════════════

def _build_user_message(project: str, log_path: str, failed_targets: list[str]) -> str:
    tgt_list = "\n".join(f"- {t}" for t in failed_targets)
    return f"""## 分诊任务

- **项目**: `{project}`
- **构建 log**: `{log_path}`（用 search_log 搜索，不要假设整段可读）
- **失败数量**: {len(failed_targets)} 个 target

## 失败的 target（需逐个判定 code / build）
{tgt_list}

## 高效分诊策略（减少步数消耗）

请按以下**批量优先**的顺序工作，避免逐个 target 线性处理：

1. 先用 search_log('undefined reference') **一次性**拿到所有 undefined reference 错误
2. 从结果中提取所有唯一符号（去重），对每个符号调用 **一次** grep_symbol 验证
3. 再用 search_log('error:') 或 search_log('fatal error') **批量**拿到其他编译错误
4. 汇总上述结果，按 target 组织成 routes 数组
5. submit_routes 提交

这样可以把步数从 ~{len(failed_targets) * 5} 降到 ~{len(failed_targets) // 3 + 15}。"""


def _normalize_routes(routes: Any, failed_targets: list[str]) -> list[dict]:
    """校验 / 规整 LLM 提交的 routes：kind 只允许 code|build，target 必须在失败集合内，
    缺失的 target 补一个默认 code route（不漏判）。"""
    valid_targets = set(failed_targets)
    out: list[dict] = []
    seen: set[str] = set()
    if isinstance(routes, list):
        for r in routes:
            if not isinstance(r, dict):
                continue
            tgt = r.get("target")
            if tgt not in valid_targets or tgt in seen:
                continue
            kind = r.get("kind")
            if kind not in ("code", "build"):
                kind = "code"
            ev = r.get("evidence")
            ev = [str(x)[:300] for x in ev][:8] if isinstance(ev, list) else []
            out.append({
                "target": tgt, "kind": kind, "evidence": ev,
                "reason": str(r.get("reason", ""))[:500],
            })
            seen.add(tgt)
    for t in failed_targets:
        if t not in seen:
            out.append({"target": t, "kind": "code", "evidence": [],
                        "reason": "LLM 未对该 target 分诊，默认归 code 待复核"})
    return out


def _make_handler(project: str, log_path: str, failed_targets: list[str]):
    """构造 run_agent_loop 的工具分发回调。"""
    def handler(name: str, args: dict, ctx: dict) -> str:
        if name == "search_log":
            return ac.search_log(
                log_path, args.get("pattern", ""),
                int(args.get("context_lines", 3)),
                int(args.get("max_hits", 20)),
            )
        if name == "grep_symbol":
            return tool_grep_symbol(project, args.get("symbol", ""),
                                    int(args.get("max_results", 20)))
        if name == "read_source":
            return tool_read_source(project, args.get("path", ""),
                                    int(args.get("start_line", 1)),
                                    int(args.get("max_lines", 200)))
        if name == "submit_routes":
            routes = _normalize_routes(args.get("routes", []), failed_targets)
            ctx["submit"](routes)
            return json.dumps({"accepted": len(routes)}, ensure_ascii=False)
        return f"[error] 未知工具 {name}"
    return handler


def agent_triage(project: str, log_path: str, failed_targets: list[str],
                 max_steps: int = 30, model: Optional[str] = None,
                 mode: Optional[str] = None) -> list[dict]:
    """分诊入口。返回 Route 列表并存档 intermediate/<project>/triage[_<mode>].json。

    mode 透传给 triage_deterministic 的 diff_products（按 mode 过滤失败 target）。
    max_steps 默认 30（从 10 增加），适合处理 ~20 个失败 target。对于更大规模失败，
    调用方应根据 len(failed_targets) 动态调整（建议 max(30, len(failed) * 1.5)）。

    无凭证 → 降级到 triage_deterministic（仍能对两个验收用例判对，因为 grep_symbol 是确定性的）。
    LLM 跑完但没 submit → 也回落到确定性分诊，保证不漏判、不崩。
    """
    routes: list[dict] = []
    if ac.deepseek_available():
        handler = _make_handler(project, log_path, failed_targets)
        user_text = _build_user_message(project, log_path, failed_targets)
        res = ac.run_agent_loop(
            SYSTEM_PROMPT, user_text, TOOLS, handler,
            model=model, max_steps=max_steps, label="triage",
        )
        if res.submitted and isinstance(res.payload, list):
            routes = res.payload
        else:
            print(f"  [triage] LLM 未正常提交（{res.stop_reason}），回落确定性分诊")
            routes = triage_deterministic(project, log_path, failed_targets, mode)
    else:
        print("  [triage] 无 DeepSeek 凭证，使用确定性分诊（grep_symbol 仍可区分真/臆造符号）")
        routes = triage_deterministic(project, log_path, failed_targets, mode)

    try:
        triage_file = f"triage_{mode}.json" if mode else "triage.json"
        (intermediate_for(project) / triage_file).write_text(
            json.dumps(routes, indent=2, ensure_ascii=False)
        )
    except OSError:
        pass
    return routes


# ══════════════════════════════════════════════════════════════════════
# CLI（调试：对现有 log 跑确定性分诊）
# ══════════════════════════════════════════════════════════════════════

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m tools.step3_agent.agent_triage <project> [failed_target ...] "
              "[--mode=focus|peer|cross]")
        sys.exit(1)
    project = sys.argv[1]
    mode = None
    targets = []
    for a in sys.argv[2:]:
        if a.startswith("--mode="):
            mode = a.split("=", 1)[1]
        else:
            targets.append(a)
    from tools.step3_agent.agent_main import diff_products, build_log_path
    if targets:
        failed = targets
    else:
        _, failed_set = diff_products(project, mode)
        failed = sorted(failed_set)
    log_path = str(build_log_path(project))
    tag = f"[{mode}]" if mode else "[legacy]"
    print(f"[triage] {project} {tag}: {len(failed)} 失败 target, log={log_path}")
    routes = agent_triage(project, log_path, failed, mode=mode)
    print(json.dumps(routes, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
