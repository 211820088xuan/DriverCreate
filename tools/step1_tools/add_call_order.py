#!/usr/bin/env python3
"""
add_call_order.py v2 — 给知识图谱的 CALLS 边补 `order` / `order_last` 属性

本脚本在 tools/ 下，通过 sys.path bootstrap 引用根目录的 config。
背景
----
图谱里 (Driver)-[:CALLS]->(API) 只记录了「调不调用」，没有顺序。骨架挖掘
（把 driver 抽象成角色序列）的本质就是顺序，所以必须先把序号补进图谱。

顺序只能从源码解析。本脚本从 PROJECTS_DIR/<project>/<driver 文件> 解析每个
driver 的 API 调用序列，写回 CALLS 边。

v1 → v2 的三处修正（依据 v1 干跑报告）
--------------------------------------
v1 结果：解析 4565，图谱 6871，图谱有但没解析出约 2300，解析出但图谱没有仅 8。
结论与原假设相反 —— **图谱是超集，是解析器漏了**。三处修正：

1. **允许 C++ 成员调用**（最大的一块）。图谱把 C++ 方法也算作 CAPI
   （schema: "CAPI 包含 C 函数、C++ 方法、类型名"），而 v1 的正则用
   `(?<![\\w.>:])` 排除了 `.foo(` / `->foo(` / `::foo(`，导致纯 C++ 项目
   几乎全军覆没：simdjson 14 个 driver 解析出 0 个，boost 39 个只出 4 个，
   未解析的全是 `empty` / `data` / `size` / `parse` / `get` 这类成员调用。
   放开后不必担心噪声 —— 图谱的 HAS_API 集合本身就是过滤器。

2. **driver 名按项目作用域比对**。v1 的 existing_calls 只用 driver 名做 key，
   而 `fuzzer.c` / `cert.cc` / `fuzz_client.c` 在多个项目里重名，导致诊断数据
   串台（cairo/fuzzer.c 的 unparsed_apis 里混进了 libsrtp 的 srtp_* 和
   wasm3 的 m3_*）。改为 (project, driver, api) 三元组。

3. **同时记录 order 与 order_last**。「首次出现」会被错误分支带偏：
   libarchive_7zip_fuzzer 里 `archive_read_free` 排第 6 位，因为
   `if (r != OK) { archive_read_free(a); return 0; }` 出现在主流程之前。
   order      = 按首次出现排序的序号（适合看「先创建后使用」）
   order_last = 按末次出现排序的序号（适合看「清理函数在末尾」）
   骨架挖掘阶段可自行选用，或两者对照识别这类早退清理。

关键设计（v1 保留）
-------------------
- **跟进一层局部 helper**：只扫 LLVMFuzzerTestOneInput 函数体不够。v1 报告
  证实这条价值很大 —— 靠它多抓到 460 个 API，且都在关键位置：
  freerdp/TestFuzzCoreClient.c 0 → 40，curl/fuzz_bufq.cc 0 → 16，
  htslib/hts_open_fuzzer.c 4 → 20，harfbuzz/hb-draw-fuzzer.cc 20 → 43。
- **用图谱过滤**：解析出的标识符里混着 libc、局部 helper、fuzzing infra。
  不自己维护黑名单，而是拿图谱里该项目 HAS_API 的集合做交集。
- **两类边分开处理**：图谱已有的补 order（默认）；解析出但图谱没有的默认
  只报告，加 --add-missing 才建新边（v1 实测仅 8 条，基本不需要）。

用法
----
    # 1. 干跑，看解析质量（不写库）——先跑这个
    python3 add_call_order.py --dry-run

    # 2. 只看一个项目的详细解析结果（调试用）
    python3 add_call_order.py --project harfbuzz --dry-run --verbose

    # 3. 确认没问题后写入 order / order_last
    python3 add_call_order.py

验收线（对照 v1）
-----------------
    平均每 driver 解析出的 API 数应从 v1 的 4.8 涨到 6.3 附近
    （= 图谱 6871 条 CALLS ÷ 1086 个 driver），且 edges_missing 保持在
    小两位数以内。到这个数说明解析器与图谱对齐。
    若涨过头（9+）而 edges_missing 暴涨，说明成员调用引入了图谱没有的噪声，
    需回头收紧 _CALL_RE。

环境变量：复用 config.py 的 NEO4J_* 配置。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

# tools/ 下的脚本用 sys.path bootstrap 引用根目录 config
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

try:
    from config import (
        NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE,
        PROJECTS_DIR,
    )
except ImportError:
    print("[error] 无法 import config，请在 driver_create 目录下运行本脚本")
    sys.exit(1)

try:
    from neo4j import GraphDatabase, basic_auth
except ImportError:
    print("[error] 需要 neo4j 驱动: pip install neo4j")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════
# 源码解析：提取 driver 的 API 调用序列
# ══════════════════════════════════════════════════════════════════════

DRIVER_EXTS = (".c", ".cc", ".cpp", ".cxx")

# libFuzzer 入口函数（解析起点）
ENTRY_FUNCS = (
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
)

# ── v2 修正 1：允许 C++ 成员调用 ──
# v1 用 (?<![\w.>:]) 排除 .foo( / ->foo( / ::foo(，但图谱把 C++ 方法也算作
# CAPI，导致纯 C++ 项目解析出 0 个。现在只排除「前一字符是标识符字符」
# （避免把 foo_bar( 拆成 bar()，靠图谱 HAS_API 集合过滤噪声。
_CALL_RE = re.compile(r'(?<![A-Za-z_0-9])([A-Za-z_][A-Za-z_0-9]*)\s*\(')

# 函数定义：ret_type name(...) {  —— 用于建立「本文件内定义的函数」索引
_FUNC_DEF_RE = re.compile(
    r'^[ \t]*'
    r'(?:(?:static|inline|extern|const|virtual|explicit|unsigned|signed|struct|'
    r'template\s*<[^>]*>)\s+)*'
    r'[A-Za-z_][\w:<>,\s\*&]*?'
    r'[\s\*&]+'
    r'(?:[A-Za-z_]\w*::)?'               # 新增：允许 ClassName:: 前缀
    r'([A-Za-z_]\w*)\s*'
    r'\([^;{]*\)\s*'
    r'(?:const\s*)?(?:noexcept\s*)?'     # 新增：noexcept
    r'(?:->\s*[\w:<>,\s\*&]+\s*)?'       # 新增：尾置返回类型
    r'\{',
    re.MULTILINE,
)

# 模块顶部，和其它正则放一起
_LAMBDA_RE = re.compile(
    r'\[[^\]\[]{0,40}\]'                 # 捕获列表 [&] [=] [this] [&a, b]
    r'\s*(?:\([^;{]*\)\s*)?'             # 可选参数列表
    r'(?:mutable\s*|constexpr\s*|noexcept\s*)*'
    r'(?:->\s*[\w:<>,\s\*&]+\s*)?'       # 可选尾置返回类型
    r'\{'
)

_ENTRY_RE = re.compile(
    r'(?:extern\s+\S*\s+)?'                                  # extern "C"
    r'\b(?:int|size_t|void)\s+'                              # 返回类型
    r'(?:LLVMFuzzerTestOneInput|LLVMFuzzerInitialize)\s*'    # 入口名
    r'\([^;{]*\)\s*'                                         # 参数（无 ; 排除声明）
    r'\{',
)

# C/C++ 语句关键字：这些后面跟 ( 但不是函数调用
_STMT_KEYWORDS = frozenset({
    'if', 'for', 'while', 'switch', 'return', 'sizeof', 'catch',
    'do', 'else', 'case', 'default', 'goto', 'break', 'continue',
    'alignof', 'typeof', 'decltype', 'static_assert', '_Static_assert',
    'defined', 'and', 'or', 'not', 'new', 'delete', 'throw',
})


def strip_noncode(code: str) -> str:
    """状态机剥离注释与字符串/字符字面量，用空格填充以保持偏移不变。

    必须做——否则注释里的示例代码、字符串里的括号都会被当成调用。
    """
    out = []
    i, n = 0, len(code)
    state = 'code'
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ''
        if state == 'code':
            if c == '/' and nxt == '/':
                out.append('  '); state = 'line_comment'; i += 2; continue
            if c == '/' and nxt == '*':
                out.append('  '); state = 'block_comment'; i += 2; continue
            if c == '"':
                out.append(' '); state = 'string'; i += 1; continue
            if c == "'":
                out.append(' '); state = 'char'; i += 1; continue
            out.append(c); i += 1; continue
        if state == 'line_comment':
            if c == '\n':
                out.append('\n'); state = 'code'
            else:
                out.append(' ')
            i += 1; continue
        if state == 'block_comment':
            if c == '*' and nxt == '/':
                out.append('  '); state = 'code'; i += 2; continue
            out.append('\n' if c == '\n' else ' '); i += 1; continue
        if state == 'string':
            if c == '\\' and nxt:
                out.append('  '); i += 2; continue
            if c == '"':
                out.append(' '); state = 'code'; i += 1; continue
            out.append('\n' if c == '\n' else ' '); i += 1; continue
        if state == 'char':
            if c == '\\' and nxt:
                out.append('  '); i += 2; continue
            if c == "'":
                out.append(' '); state = 'code'; i += 1; continue
            out.append('\n' if c == '\n' else ' '); i += 1; continue
    return ''.join(out)


def find_matching_brace(text: str, open_idx: int) -> int:
    """从 text[open_idx] == '{' 出发，返回配对 '}' 的下标；找不到返回 -1。

    输入必须是 strip_noncode 处理过的文本（否则字符串里的花括号会算数）。
    """
    if open_idx >= len(text) or text[open_idx] != '{':
        return -1
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
    return -1


def index_local_functions(clean: str) -> dict[str, tuple[int, int]]:
    """建立「本文件内定义的函数名 → (函数体起止下标)」索引。

    用于展开局部 helper。clean 必须是 strip_noncode 后的文本。
    """
    funcs: dict[str, tuple[int, int]] = {}
    for m in _FUNC_DEF_RE.finditer(clean):
        name = m.group(1)
        if name in _STMT_KEYWORDS:
            continue
        brace_idx = clean.find('{', m.end() - 1)
        if brace_idx == -1:
            continue
        end_idx = find_matching_brace(clean, brace_idx)
        if end_idx == -1:
            continue
        # 同名函数（重载/条件编译分支）只记第一个
        funcs.setdefault(name, (brace_idx + 1, end_idx))
    return funcs


def extract_call_sequence(clean: str, body_range: tuple[int, int],
                          local_funcs: dict[str, tuple[int, int]],
                          max_depth: int = 1,
                          project_texts: Optional[dict] = None,
                          project_funcs: Optional[dict] = None) -> list[str]:
    """从函数体里按出现顺序提取调用序列。

    展开三类块：
      1. 具名局部 helper（查 local_funcs 表，本文件内）
      2. lambda 体（就地展开，匿名所以查不了表）
      3. 类成员函数（也在 local_funcs 里，靠放宽的 _FUNC_DEF_RE 收进来）

    v3 新增：跨文件 helper 跟进。project_texts/project_funcs 提供项目级函数索引，
    当 helper 不在 local_funcs 时，查 project_funcs 跨文件跟进（修 wuffs 共享 fuzzlib 模式：
    入口在 fuzzlib.c，实际逻辑在 *_fuzzer.c 的 helper 里）。

    lambda 展开不消耗 depth 预算——它在词法上就属于当前函数体，
    只是被回调包了一层，语义上仍是同一层的代码。
    """
    result: list[str] = []
    visiting: set[str] = set()

    def resolve_helper(name: str) -> Optional[tuple[str, int, int]]:
        """返回 (clean_text, body_start, body_end) 或 None。先查本文件，再查项目级。"""
        if name in local_funcs:
            hs, he = local_funcs[name]
            return (clean, hs, he)
        if project_funcs and name in project_funcs and project_texts:
            fp, hs, he = project_funcs[name]
            if fp in project_texts:
                return (project_texts[fp], hs, he)
        return None

    def walk(walk_clean: str, start: int, end: int, depth: int):
        # 先扫出本区间内所有 lambda 体的范围，扫描时跳过外层、就地递归进去
        lambda_spans = []
        pos = start
        while pos < end:
            m = _LAMBDA_RE.search(walk_clean, pos, end)
            if not m:
                break
            brace = walk_clean.rfind('{', m.start(), m.end())
            close = find_matching_brace(walk_clean, brace)
            if close == -1 or close > end:
                pos = m.end()
                continue
            lambda_spans.append((brace + 1, close))
            pos = close + 1

        # 按出现顺序遍历「普通区间」和「lambda 区间」
        segments = []
        cursor = start
        for ls, le in lambda_spans:
            if cursor < ls:
                segments.append(('plain', cursor, ls))
            segments.append(('lambda', ls, le))
            cursor = le + 1
        if cursor < end:
            segments.append(('plain', cursor, end))

        for kind, s, e in segments:
            if kind == 'lambda':
                walk(walk_clean, s, e, depth)      # lambda 不消耗 depth
                continue
            for m in _CALL_RE.finditer(walk_clean, s, e):
                name = m.group(1)
                if name in _STMT_KEYWORDS:
                    continue
                p = m.start(1) - 1
                while p >= s and walk_clean[p] in ' \t':
                    p -= 1
                if p >= s and walk_clean[p] in '*&':
                    continue

                helper = resolve_helper(name)
                if helper and depth < max_depth and name not in visiting:
                    result.append(name)
                    visiting.add(name)
                    hc, hs, he = helper
                    walk(hc, hs, he, depth + 1)
                    visiting.discard(name)
                else:
                    result.append(name)

    walk(clean, body_range[0], body_range[1], 0)
    return result


def parse_driver_file(path: Path, max_depth: int = 1,
                      project_texts: Optional[dict] = None,
                      project_funcs: Optional[dict] = None) -> dict:
    """解析单个 driver 源文件，返回 {sequence, entry_found, n_local_funcs}。

    v3 修正：解析【所有】入口函数体（不只第一个），按 Initialize → TestOneInput 顺序拼接。
    修 v2 漏掉 LLVMFuzzerInitialize 里调用的问题（libxml2 的 xmlInitParser 等）。

    project_texts/project_funcs（v3 新增）：项目级跨文件函数索引，支持跟进到其它文件
    的 helper（修 wuffs 共享 fuzzlib 模式）。

    sequence 是按源码顺序的标识符列表（未过滤）。
    """
    try:
        raw = path.read_text(errors='ignore')
    except OSError as e:
        return {"sequence": [], "entry_found": False, "error": str(e)}

    clean = strip_noncode(raw)
    local_funcs = index_local_functions(clean)

    # 找所有入口函数体（v3：不止第一个）
    entry_hits = []
    for m in _ENTRY_RE.finditer(clean):
        brace_idx = clean.rfind('{', m.start(), m.end())
        if brace_idx == -1:
            continue
        end_idx = find_matching_brace(clean, brace_idx)
        if end_idx == -1:
            continue
        is_main = 'LLVMFuzzerTestOneInput' in clean[m.start():m.end()]
        entry_hits.append((0 if is_main else 1, brace_idx + 1, end_idx))

    body_ranges = []
    if entry_hits:
        entry_hits.sort()          # TestOneInput 优先（语义上 Initialize 在前，但调用顺序
                                    # 的 first/last 排名会自然处理，这里先收集所有体）
        body_ranges = [(h[1], h[2]) for h in entry_hits]
    else:
        for entry in ENTRY_FUNCS:  # 兜底：通用函数索引
            if entry in local_funcs:
                body_ranges = [local_funcs[entry]]
                break

    if not body_ranges:
        return {"sequence": [], "entry_found": False,
                "n_local_funcs": len(local_funcs)}

    # v3：拼接所有入口函数体的调用序列
    seq: list[str] = []
    for br in body_ranges:
        seq.extend(extract_call_sequence(clean, br, local_funcs, max_depth,
                                          project_texts, project_funcs))
    return {"sequence": seq, "entry_found": True,
            "n_local_funcs": len(local_funcs)}


# ── v2 修正 3：同时算 order（首次出现）与 order_last（末次出现）──

def rank_by_first_and_last(seq: list[str], allowed: set[str]) -> list[dict]:
    """按图谱 API 集合过滤，返回每个 API 的两个序号。

    order      = 按「首次出现位置」排序后的名次（0,1,2...）
    order_last = 按「末次出现位置」排序后的名次（0,1,2...）

    为什么要两个：「首次出现」会被错误分支带偏。libarchive_7zip_fuzzer 里
    archive_read_free 首次出现在第 6 位，因为主流程之前有
    `if (r != OK) { archive_read_free(a); return 0; }`；但它末次出现在结尾，
    order_last 能正确反映「清理函数在最后」。骨架挖掘可自行选用或两者对照。

    返回列表按 order 升序（即按首次出现顺序），每项 {api, order, order_last}。
    """
    first_pos: dict[str, int] = {}
    last_pos: dict[str, int] = {}
    for i, name in enumerate(seq):
        if name not in allowed:
            continue
        if name not in first_pos:
            first_pos[name] = i
        last_pos[name] = i

    if not first_pos:
        return []

    by_first = sorted(first_pos, key=first_pos.get)
    by_last = sorted(last_pos, key=last_pos.get)
    last_rank = {name: i for i, name in enumerate(by_last)}

    return [
        {"api": name, "order": i, "order_last": last_rank[name]}
        for i, name in enumerate(by_first)
    ]


# ══════════════════════════════════════════════════════════════════════
# 图谱侧
# ══════════════════════════════════════════════════════════════════════

def fetch_graph_state(session) -> dict:
    """一次性拉取全图状态，避免逐 driver 查询。

    返回 {
      "project_apis":   {project: set(api_name)},
      "driver_files":   {project: set(driver_name)},
      "existing_calls": {(project, driver_name, api_name)},   # v2: 带项目作用域
    }
    """
    print("[graph] 拉取项目 API 集合...")
    project_apis: dict[str, set[str]] = {}
    result = session.run("""
        MATCH (lib:Library)-[:HAS_API]->(a)
        WHERE a:CAPI OR a:API OR a:RustAPI
        RETURN lib.name AS project, collect(DISTINCT a.name) AS apis
    """)
    for r in result:
        project_apis[r["project"]] = set(x for x in (r["apis"] or []) if x)
    print(f"        {len(project_apis)} 个项目，"
          f"{sum(len(v) for v in project_apis.values())} 个 API")

    print("[graph] 拉取 driver 列表...")
    driver_files: dict[str, set[str]] = {}
    result = session.run("""
        MATCH (lib:Library)-[:HAS_DRIVER]->(d)
        RETURN lib.name AS project, collect(DISTINCT d.name) AS drivers
    """)
    for r in result:
        driver_files[r["project"]] = set(x for x in (r["drivers"] or []) if x)
    print(f"        {sum(len(v) for v in driver_files.values())} 个 driver")

    # ── v2 修正 2：CALLS 边按 (project, driver, api) 三元组存 ──
    # v1 只用 driver 名做 key，而 fuzzer.c / cert.cc / fuzz_client.c 在多个
    # 项目里重名 → 诊断数据串台（cairo/fuzzer.c 的 unparsed_apis 里混进了
    # libsrtp 的 srtp_* 和 wasm3 的 m3_*）。
    print("[graph] 拉取已有 CALLS 边（带项目作用域）...")
    existing_calls: set[tuple[str, str, str]] = set()
    result = session.run("""
        MATCH (lib:Library)-[:HAS_DRIVER]->(d)-[:CALLS]->(a)
        RETURN lib.name AS project, d.name AS driver, a.name AS api
    """)
    for r in result:
        if r["project"] and r["driver"] and r["api"]:
            existing_calls.add((r["project"], r["driver"], r["api"]))
    print(f"        {len(existing_calls)} 条 CALLS 边")

    return {
        "project_apis": project_apis,
        "driver_files": driver_files,
        "existing_calls": existing_calls,
    }


def write_orders(session, project: str, driver_name: str,
                 rows: list[dict], add_missing: bool) -> tuple[int, int]:
    """把 order / order_last 写回图谱。返回 (更新的边数, 新建的边数)。

    rows: [{api, order, order_last}, ...]
    """
    if not rows:
        return 0, 0

    # 1. 更新已有边
    res = session.run("""
        UNWIND $rows AS row
        MATCH (lib:Library {name: $project})-[:HAS_DRIVER]->(d {name: $driver})
        MATCH (lib)-[:HAS_API]->(a {name: row.api})
        MATCH (d)-[r:CALLS]->(a)
        SET r.order = row.order, r.order_last = row.order_last
        RETURN count(r) AS n
    """, rows=rows, project=project, driver=driver_name)
    updated = res.single()["n"] or 0

    created = 0
    if add_missing:
        res = session.run("""
            UNWIND $rows AS row
            MATCH (lib:Library {name: $project})-[:HAS_DRIVER]->(d {name: $driver})
            MATCH (lib)-[:HAS_API]->(a {name: row.api})
            MERGE (d)-[r:CALLS]->(a)
              ON CREATE SET r.order = row.order, r.order_last = row.order_last,
                            r.source = 'add_call_order'
              ON MATCH  SET r.order = row.order, r.order_last = row.order_last
            RETURN count(r) AS n
        """, rows=rows, project=project, driver=driver_name)
        total = res.single()["n"] or 0
        created = max(0, total - updated)

    return updated, created


# ══════════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════════

def process_project(project: str, state: dict, args) -> dict:
    """处理一个项目的全部 driver，返回统计。"""
    proj_dir = PROJECTS_DIR / project
    if not proj_dir.is_dir():
        return {"skipped": "no_source_dir"}

    allowed = state["project_apis"].get(project, set())
    if not allowed:
        return {"skipped": "no_api_in_graph"}

    graph_drivers = state["driver_files"].get(project, set())
    existing = state["existing_calls"]

    stat = {
        "drivers_on_disk": 0,
        "drivers_matched": 0,
        "drivers_no_entry": 0,
        "apis_parsed": 0,
        "edges_existing": 0,
        "edges_missing": 0,
        "edges_updated": 0,
        "edges_created": 0,
        "helper_expanded": 0,
        "member_call_gain": 0,   # v2 新增：靠成员调用多抓到的数量（诊断用）
        "reorder_diff": 0,       # v2 新增：order 与 order_last 名次不同的 API 数
        "details": [],
    }

    files = []
    for ext in DRIVER_EXTS:
        files.extend(sorted(proj_dir.glob(f"*{ext}")))

    # ── v3 第一遍：建项目级跨文件函数索引 ──
    # 修 wuffs 共享 fuzzlib 模式：入口在 fuzzlib.c，实际逻辑在 *_fuzzer.c 的 helper 里。
    # 扫所有 driver 文件，建 {name: (file_path, body_start, body_end)} 索引，
    # parse_driver_file 跟进 helper 时能跨文件查到。
    project_texts: dict[Path, str] = {}
    project_funcs: dict[str, tuple[Path, int, int]] = {}
    for f in files:
        if "standalone" in f.name.lower():
            continue
        if f.name not in graph_drivers:
            continue
        try:
            raw = f.read_text(errors='ignore')
        except OSError:
            continue
        clean = strip_noncode(raw)
        project_texts[f] = clean
        for name, (s, e) in index_local_functions(clean).items():
            # 同名函数（重载/多文件同名）只记第一个；entry 函数不进索引（避免自递归）
            if name not in project_funcs and name not in ENTRY_FUNCS:
                project_funcs[name] = (f, s, e)

    for f in files:
        if "standalone" in f.name.lower():
            continue
        stat["drivers_on_disk"] += 1

        # 图谱里的 driver 名就是文件名（如 "spng_read_fuzzer.c"）
        if f.name not in graph_drivers:
            if args.verbose:
                print(f"    [skip] {f.name} 不在图谱 driver 列表里")
            continue
        stat["drivers_matched"] += 1

        # 解析两次：不展开 helper vs 展开，用于量化 helper 的贡献
        parsed_flat = parse_driver_file(f, max_depth=0,
                                         project_texts=project_texts,
                                         project_funcs=project_funcs)
        parsed = parse_driver_file(f, max_depth=args.helper_depth,
                                   project_texts=project_texts,
                                   project_funcs=project_funcs)

        if not parsed["entry_found"]:
            stat["drivers_no_entry"] += 1
            stat["details"].append({
                "driver": f.name, "parsed": 0, "no_entry": True,
                "in_graph_not_parsed": len({
                    a for (p, d, a) in existing if p == project and d == f.name}),
            })
            if args.verbose:
                print(f"    [warn] {f.name} 未找到入口函数")
            continue

        rows = rank_by_first_and_last(parsed["sequence"], allowed)
        rows_flat = rank_by_first_and_last(parsed_flat["sequence"], allowed)
        ordered = [r["api"] for r in rows]

        stat["helper_expanded"] += max(0, len(rows) - len(rows_flat))
        stat["apis_parsed"] += len(rows)
        stat["reorder_diff"] += sum(
            1 for r in rows if r["order"] != r["order_last"])

        # v2: 项目作用域比对
        n_existing = sum(1 for a in ordered if (project, f.name, a) in existing)
        stat["edges_existing"] += n_existing
        stat["edges_missing"] += len(ordered) - n_existing

        # 图谱有边但源码没解析出来的 API（反向缺口，解析质量的核心指标）
        graph_apis_for_driver = {
            a for (p, d, a) in existing if p == project and d == f.name}
        unparsed = graph_apis_for_driver - set(ordered)

        detail = {
            "driver": f.name,
            "parsed": len(rows),
            "parsed_no_helper": len(rows_flat),
            "in_graph": n_existing,
            "missing_in_graph": len(ordered) - n_existing,
            "in_graph_not_parsed": len(unparsed),
            "sequence": ordered,
        }
        # 首末次名次不同的 API：暴露「早退分支里的清理调用」
        reordered = [
            {"api": r["api"], "order": r["order"], "order_last": r["order_last"]}
            for r in rows if r["order"] != r["order_last"]
        ]
        if reordered:
            detail["reordered"] = reordered[:10]
        if unparsed:
            detail["unparsed_apis"] = sorted(unparsed)
        stat["details"].append(detail)

        if args.verbose:
            print(f"    [{f.name}] 解析 {len(rows)} 个 API "
                  f"(不展开 helper: {len(rows_flat)}) | "
                  f"图谱已有 {n_existing} | 图谱缺 {len(ordered) - n_existing} | "
                  f"图谱有但没解析出 {len(unparsed)}")
            print(f"        序列: {' → '.join(ordered[:12])}"
                  f"{' ...' if len(ordered) > 12 else ''}")
            if reordered:
                print(f"        首末次名次不同: "
                      f"{[(r['api'], r['order'], r['order_last']) for r in reordered[:4]]}")
            if unparsed:
                print(f"        未解析到: {sorted(unparsed)[:8]}")

        if not args.dry_run:
            u, c = write_orders(args._session, project, f.name, rows,
                                args.add_missing)
            stat["edges_updated"] += u
            stat["edges_created"] += c

    return stat


def main():
    ap = argparse.ArgumentParser(
        description="给图谱 CALLS 边补 order / order_last 属性")
    ap.add_argument("--project", help="只处理指定项目（默认全部）")
    ap.add_argument("--dry-run", action="store_true",
                    help="只解析并报告，不写库。第一次务必先跑这个")
    ap.add_argument("--add-missing", action="store_true",
                    help="解析出但图谱没有的 CALLS 边，也建出来"
                         "（v1 实测仅 8 条，通常不需要）")
    ap.add_argument("--helper-depth", type=int, default=1,
                    help="局部 helper 展开层数（默认 1；0 = 只扫入口函数体）")
    ap.add_argument("--verbose", action="store_true", help="打印每个 driver 的解析明细")
    ap.add_argument("--report", default="call_order_report.json",
                    help="报告输出路径")
    args = ap.parse_args()

    if not NEO4J_PASSWORD:
        print("[error] NEO4J_PASSWORD 未设置")
        sys.exit(1)

    mode = "DRY-RUN（不写库）" if args.dry_run else (
        "写库 + 补建缺失边" if args.add_missing else "写库（只更新已有边）")
    print(f"=== add_call_order.py v2 | 模式: {mode} | "
          f"helper 展开: {args.helper_depth} 层 ===\n")

    driver_conn = GraphDatabase.driver(
        NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))

    totals = Counter()
    all_stats: dict[str, dict] = {}
    skipped_names: dict[str, list[str]] = {}   # v2: 记录跳过的项目名

    with driver_conn.session(database=NEO4J_DATABASE) as session:
        args._session = session
        state = fetch_graph_state(session)

        if args.project:
            projects = [args.project]
        else:
            on_disk = {p.name for p in PROJECTS_DIR.iterdir() if p.is_dir()} \
                if PROJECTS_DIR.is_dir() else set()
            projects = sorted(on_disk & set(state["driver_files"].keys()))
            print(f"\n[main] 磁盘 {len(on_disk)} 个项目目录，"
                  f"图谱 {len(state['driver_files'])} 个项目有 driver，"
                  f"交集 {len(projects)} 个\n")

        for i, project in enumerate(projects, 1):
            if args.verbose or i % 20 == 0 or len(projects) < 20:
                print(f"[{i}/{len(projects)}] {project}")
            stat = process_project(project, state, args)
            if "skipped" in stat:
                totals[f"skipped_{stat['skipped']}"] += 1
                skipped_names.setdefault(stat["skipped"], []).append(project)
                continue
            all_stats[project] = stat
            for k in ("drivers_on_disk", "drivers_matched", "drivers_no_entry",
                      "apis_parsed", "edges_existing", "edges_missing",
                      "edges_updated", "edges_created", "helper_expanded",
                      "reorder_diff"):
                totals[k] += stat.get(k, 0)

    driver_conn.close()

    # ── 报告 ──
    print(f"\n{'=' * 62}")
    print("汇总")
    print(f"{'=' * 62}")
    print(f"  处理项目            : {len(all_stats)}")
    print(f"  磁盘 driver 文件    : {totals['drivers_on_disk']}")
    print(f"  与图谱匹配上的      : {totals['drivers_matched']}")
    print(f"  未找到入口函数      : {totals['drivers_no_entry']}")
    print(f"  解析出的 API 调用   : {totals['apis_parsed']}")
    print(f"    其中靠展开 helper 多抓到: {totals['helper_expanded']}")
    print(f"  图谱已有对应边      : {totals['edges_existing']}")
    print(f"  图谱缺失的边        : {totals['edges_missing']}")
    print(f"  首末次名次不同的 API: {totals['reorder_diff']}"
          f"  （早退分支里的清理调用；order_last 更能反映真实收尾顺序）")
    if not args.dry_run:
        print(f"  实际更新 order      : {totals['edges_updated']}")
        print(f"  实际新建边          : {totals['edges_created']}")

    # v2: 跳过的项目打名字，便于排查
    for reason, names in sorted(skipped_names.items()):
        print(f"  跳过（{reason}）: {len(names)} 个 → {', '.join(sorted(names)[:12])}"
              f"{' ...' if len(names) > 12 else ''}")

    # 解析质量诊断
    matched = totals['drivers_matched'] or 1
    avg = totals['apis_parsed'] / matched
    print(f"\n  平均每 driver 解析出 {avg:.1f} 个 API")
    print(f"  （v1 为 4.8；目标约 6.3 = 图谱 6871 条 CALLS ÷ 1086 个 driver）")
    if avg < 5.5:
        print(f"  [!] 低于预期 —— 成员调用修正可能没生效，检查 _CALL_RE")
    elif avg > 8.5 and totals['edges_missing'] > 500:
        print(f"  [!] 高于预期且 edges_missing 大 —— 成员调用可能引入噪声，"
              f"考虑收紧 _CALL_RE")
    else:
        print(f"  [ok] 在预期区间，解析器与图谱已对齐")

    report_path = Path(args.report)
    report_path.write_text(json.dumps({
        "version": 2,
        "mode": mode,
        "helper_depth": args.helper_depth,
        "totals": dict(totals),
        "skipped": skipped_names,
        "projects": all_stats,
    }, indent=2, ensure_ascii=False))
    print(f"\n  详细报告 → {report_path}")

    if args.dry_run:
        print(f"\n  下一步：")
        print(f"    1. 确认平均数落在 6.3 附近、edges_missing 仍是小两位数")
        print(f"    2. 抽查 boost / simdjson / icu 这类纯 C++ 项目，"
              f"看是否从 0 变成有值")
        print(f"    3. 确认无误后去掉 --dry-run 正式写入")


if __name__ == "__main__":
    main()