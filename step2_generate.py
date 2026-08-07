#!/usr/bin/env python3
"""
Step 2: Agent 驱动合成 —— 模板 + API 调用序列 → LLM 生成 fuzz driver

输入: project_name
依赖: intermediate/<project>/scored.json, intermediate/<project>/template.json
      (由 step1_prepare.py 产出；build_profile.json / fuzzing_headers.json 可选)
功能:
  Phase A: 加载驱动模板（step1 提取的 template.json，或直接从 projects/ 解析）
  Phase B: 设计 API 调用序列（优先未测 API，按依赖关系与领域分组排序）
  Phase C: 并行调用 LLM 生成 N 个 driver（两阶段：快速模型 → 强模型兜底 + 编译反馈重试）

输出: output/<project>/<领域>_crfuzzer.{c,cpp}  (多个) + intermediate/<project>/manifest.json
"""

import sys
import json
import os
import re
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import (
    INTERMEDIATE_DIR, OUTPUT_DIR, SRC_DIR,
    LLM_PROVIDER, DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_FAST_MODEL,
    VENDOR_SKIP_DIRS, MODES, ROLES,
    intermediate_for, output_for, plan_path,
)
from plan_loader import load_plan, PLAN_VERSION


# ─── Phase A: 模板处理 ────────────────────────────────────────────

def load_template(project):
    """加载 step1 提取的模板"""
    template_file = INTERMEDIATE_DIR / project / "template.json"
    if template_file.exists():
        return json.loads(template_file.read_text())
    return {}


def derive_driver_name(sequence, template_data, project, existing_names=None):
    """从 API 调用序列生成简洁有意义的 driver 名称"""
    if existing_names is None:
        existing = set()
    else:
        existing = existing_names

    name = _derive_name_fallback(sequence, project)

    base = name
    suffix = 2
    while name in existing:
        stem = re.sub(r'_v\d+_crfuzzer$', '_crfuzzer', base)
        stem = stem.replace('_crfuzzer', '')
        name = f"{stem}_v{suffix}_crfuzzer"
        suffix += 1

    existing.add(name)
    return name


def _derive_name_fallback(sequence, project):
    """无 LLM 时的回退命名: 从 API 序列提取关键词"""
    primary = [s["api"] for s in sequence if s.get("untested")][:3]
    if not primary:
        primary = [s["api"] for s in sequence[:3]]

    # 尝试提取有意义的词
    for api in primary:
        # snake_case: 取第二部分
        parts = api.split('_')
        for p in parts[1:3]:
            if len(p) >= 3 and p.lower() not in ('new', 'get', 'set', 'free', 'init', 'add', 'del'):
                return f"{p.lower()}_crfuzzer"
        # CamelCase: xmlNewDoc → new_doc
        words = re.findall(r'[A-Z][a-z]+', api)
        meaningful = [w.lower() for w in words
                      if w.lower() not in ('new', 'get', 'set', 'free', 'init', 'add', 'del')]
        if meaningful:
            return f"{'_'.join(meaningful[:2])}_crfuzzer"

    return f"{project.replace('-', '_')}_crfuzzer"


def build_signature_cache(src_dir):
    """一次遍历所有头文件，缓存函数声明、结构体定义、初始化宏、常量、枚举、typedef"""
    cache = {}        # function_name → "ret_type func_name(param_type *param, ...)"
    structs = {}      # struct_name → "{ field_type field1; ... }"
    defaults = {}     # type_name → "MACRO_NAME" (init macro for that type)
    alloc_funcs = {}  # type_name → ["alloc_func1", "free_func1", ...]
    enums = {}        # enum_name → "VAL1, VAL2, ..." or inline values
    typedefs = {}     # type_name → "original_type"
    constants = {}    # CONST_NAME → "value" (project-relevant #define constants)
    func_headers = {} # function_name → "include/path/to/header.h"
    type_headers = {} # type_name → "header.h" basename（类型定义所在头，用于可见性验证）
    include_graph = {}  # header.h → [被它 include 的 header.h basename]（传递闭包）
    static_inline_funcs = set()  # 头文件里 static inline 定义的函数（不进导出符号但可直接使用）

    print(f"  [cache] 扫描头文件建立签名缓存...")
    all_headers = {}
    for root, dirs, files in os.walk(src_dir):
        for f in files:
            if f.endswith(('.h', '.hpp', '.hh', '.hxx')):
                hpath = os.path.join(root, f)
                try:
                    text = open(hpath, 'r', errors='ignore').read()
                except Exception:
                    continue
                # include 图（同时跟踪 "..." 和 <...>，用于类型可见性传递闭包）
                include_graph[f] = [os.path.basename(i)
                                    for i in re.findall(r'#\s*include\s+[<"]([^>"]+)[>"]', text)]
                # 函数/类型提取仍只用 .h/.hpp（避免 .hh 内部实现污染签名）
                if f.endswith(('.h', '.hpp')):
                    all_headers[f] = text

    for fname, content in all_headers.items():
        # ── 0. static inline / FUZZ_STATIC 采集（可豁免 exported 硬门） ──
        for m in re.finditer(
            r'(?:static\s+inline|inline\s+static|FUZZ_STATIC(?:\s+\w+)?)\s+'
            r'(?:const\s+|unsigned\s+|signed\s+|struct\s+\w+\s+|[A-Z]\w*\s+|\w+\s+)*'
            r'([A-Za-z_]\w*)\s*\(',
            content
        ):
            static_inline_funcs.add(m.group(1))

        # ── 1. 函数名发现（宽匹配，保覆盖率） ──
        for m in re.finditer(r'\b(\w+)\s*\(', content):
            name = m.group(1)
            if name not in cache and re.match(r'^[a-zA-Z_]\w*$', name):
                if name not in ('if', 'while', 'for', 'switch', 'return', 'sizeof'):
                    start = max(0, m.start() - 50)
                    prefix = content[start:m.start()].replace('\n', ' ').strip()
                    prefix = re.sub(r'^.*?(\w+\s+)?(\w+\s*)$', r'\1\2', prefix)
                    cache[name] = (prefix + '(').strip()
                    func_headers[name] = fname

        # ── 2. 增强签名（精确匹配，覆盖简单匹配） ──
        # 支持指针返回类型贴名（如 `struct X *funcname`）和多行参数
        for m in re.finditer(
            r'(?:BLOSC_EXPORT\s+|EXTERN\s+|NDPI_EXPORT\s+|extern\s+|API\s+)?'
            r'([\w\s*]+?)\s+(\*{0,3})\s*'  # 返回类型 + 可选指针（单独捕获，回填返回类型）
            r'(\w+)\s*\(([^)]*)\)',        # 函数名 + 参数（[^)] 天然跨行）
            content
        ):
            ret_type, ret_ptr, name, params = m.groups()
            # 把贴在函数名前的指针 * 补回返回类型（否则 `struct X *f` 签名丢指针）
            ret_type = (ret_type.strip() + ' ' + ret_ptr).strip() if ret_ptr else ret_type.strip()
            if not re.match(r'^[a-zA-Z_]\w*$', name):
                continue
            if name in ('if', 'while', 'for', 'switch', 'return'):
                continue
            # 只覆盖那些有完整参数信息的
            if params.strip() and params.strip() != 'void':
                clean_params = re.sub(r'\s+', ' ', params.strip())
                sig = f"{ret_type} {name}({clean_params})"
                cache[name] = sig  # 覆盖简单匹配
                func_headers[name] = fname

        # ── 结构体定义 ──
        for m in re.finditer(
            r'(?:typedef\s+)?struct\s+(?:\w+\s*)?\{([^}]+)\}\s*(\w+)\s*;',
            content, re.DOTALL
        ):
            body, sname = m.groups()
            # 提取字段名和类型
            fields = re.findall(r'(\w[\w\s*]+?)\s+(\w+)\s*;', body)
            field_list = "; ".join(f"{t.strip()} {n}" for t, n in fields[:8])
            if field_list:
                structs[sname] = f"struct {sname} {{ {field_list}; ... }}"
            type_headers.setdefault(sname, fname)  # 记录定义头

        # ── 默认值/初始化宏/常量 ──
        # #define 形式
        for m in re.finditer(
            r'#define\s+((?:\w+_)?(\w+)_(?:DEFAULTS|INIT|INITIALIZER))\s+(.+)',
            content
        ):
            macro_name, type_hint, value = m.groups()
            value = value.strip().rstrip('\\').strip()
            if type_hint.upper() in ('CPARAMS', 'DPARAMS', 'STORAGE', 'CTX', 'CONTEXT', 'CONFIG', 'OPTIONS', 'PARAMS', 'IO', 'STDIO'):
                defaults[type_hint.lower()] = macro_name

        # static const TYPE NAME_DEFAULTS = {...} 形式
        for m in re.finditer(
            r'static\s+const\s+(\w+)\s+((?:\w+_)?(\w+)_DEFAULTS)\s*=',
            content
        ):
            type_name, macro_name, type_hint = m.groups()
            if type_hint.upper() in ('CPARAMS', 'DPARAMS', 'STORAGE', 'CTX', 'CONTEXT', 'CONFIG', 'OPTIONS', 'PARAMS', 'IO', 'STDIO', 'STDIO_MMAP'):
                # 同时用类型名和 hint 做 key，方便从函数签名匹配
                defaults[type_hint.lower()] = macro_name
                defaults[type_name.lower()] = macro_name

        # ── 枚举定义 ──
        for m in re.finditer(
            r'typedef\s+enum\s*(?:\w+\s*)?\{([^}]+)\}\s*(\w+)\s*;',
            content, re.DOTALL
        ):
            body, enum_name = m.groups()
            vals = re.findall(r'(\w+)\s*(?:=|,|$)', body)
            if vals:
                enums[enum_name] = ", ".join(vals[:15])
            type_headers.setdefault(enum_name, fname)  # 记录定义头

        # ── typedef 别名 ──
        for m in re.finditer(
            r'typedef\s+(?!enum|struct)([\w\s*]+?)\s+(\w+)\s*;',
            content
        ):
            original, alias = m.groups()
            original = ' '.join(original.split()).strip()
            if original and not original.startswith('__') and not alias.startswith('_'):
                typedefs[alias] = original
                type_headers.setdefault(alias, fname)  # 记录定义头

        # ── 指针 typedef ──
        for m in re.finditer(
            r'typedef\s+struct\s+\w+\s*\*?\s*(\w+)\s*;',
            content
        ):
            typedefs[m.group(1)] = f"struct {m.group(1).replace('Ptr', '').replace('Ptr', '')} *"
            type_headers.setdefault(m.group(1), fname)  # 记录定义头

        # ── 项目相关常量 (#define) ──
        for m in re.finditer(
            r'#define\s+((?!(?:_\w|__|_H_|_H__|_\d))[A-Z][A-Z0-9_]{3,40})\s+([-+]?\d+(?:u|ull|ll|U|ULL|LL)?)',
            content
        ):
            const_name, const_val = m.group(1), m.group(2)
            if not re.search(r'INCLUDE|HEADER|GUARD|DEPRECATED|EXPORT|INTERNAL', const_name, re.I):
                if const_name not in constants:
                    constants[const_name] = const_val

    # ── 关联 alloc/free 函数 ──
    for name in cache:
        for pattern, role in [(r'(\w+)_(?:new|alloc|create|init|open)', 'alloc'),
                              (r'(\w+)_(?:free|destroy|close|cleanup|release)', 'free')]:
            m = re.match(pattern, name)
            if m:
                type_name = m.group(1)
                alloc_funcs.setdefault(type_name, []).append(name)

    return {
        "functions": cache,
        "structs": structs,
        "defaults": defaults,
        "alloc_funcs": alloc_funcs,
        "enums": enums,
        "typedefs": typedefs,
        "constants": constants,
        "func_headers": func_headers,
        "type_headers": type_headers,
        "include_graph": include_graph,
        "static_inline_funcs": static_inline_funcs,
    }


def load_scored_signatures(project):
    """从 scored.json 读取图谱提供的权威签名映射：api_name -> item。
    只收「有签名且 has_info=True」的条目；没签名的不进这里，
    会在 lookup_signatures 里回落到源码正则，再没有就被自然过滤掉（= 不喂给 LLM）。"""
    sigs = {}
    p = INTERMEDIATE_DIR / project / "scored.json"
    if not p.exists():
        return sigs
    try:
        data = json.loads(p.read_text())
    except Exception:
        return sigs
    for item in data.get("scored_apis", []):
        name = item.get("api")
        if name and item.get("signature") and item.get("has_info"):
            sigs[name] = item
    return sigs


def _format_scored_sig(name, info):
    """把 scored.json 的权威签名格式化成喂给 LLM 的文本（签名 + 用途）。

    header 指引由 header_map_section 统一提供，这里不再附带 #include 提示。
    """
    sig = (info.get("signature") or "").strip()
    if sig and "(" not in sig:
        sig = sig + "("
    lines = [sig if sig else f"/* 无签名 */ {name}("]
    desc = (info.get("description") or "").strip()
    if desc:
        lines.append(f"    // 用途: {desc[:160]}")
    return "\n".join(lines)

def lookup_signatures(cache, api_names, scored_sigs=None):
    """从缓存中查询 API 签名 + 关联信息（含头文件、结构体、枚举、typedef、常量）"""
    funcs = cache.get("functions", cache)  # 兼容旧格式
    func_headers = cache.get("func_headers", {})
    result = {}
    scored_sigs = scored_sigs or {}
    for name in set(api_names):
        if name in scored_sigs:                          # ← 新增：图谱权威签名优先
            result[name] = _format_scored_sig(name, scored_sigs[name])
            continue

        if name in funcs:
            sig = funcs[name]
            if '(' not in sig:
                sig = sig + '('

            # 头文件信息放在最前面（最重要）
            hdr = func_headers.get(name, "")
            if hdr:
                result[name] = f"// #include \"{hdr}\"\n{sig}"
            else:
                result[name] = sig

            # 附带结构体/默认值信息
            extra = []
            for ptype in re.findall(r'(\w+)\s*\*', sig):
                if ptype.lower() in cache.get("defaults", {}):
                    extra.append(f"    [默认初始化: {cache['defaults'][ptype.lower()]}]")
                if ptype in cache.get("structs", {}):
                    extra.append(f"    [{cache['structs'][ptype]}]")
            if extra:
                result[name] += "\n" + "\n".join(extra[:2])
    return result


def build_header_api_map(src_dir, api_names):
    """为每个 API 找到声明它的公开头文件（精确映射）。

    只扫 include/ 子目录（公开 header），跳过 blosc/、plugins/ 等内部子目录。
    返回去掉 include/ 前缀的相对路径（如 blosc2.h、blosc2/blosc2-stdio.h）。
    """
    api_to_header = {}
    if not api_names:
        return api_to_header

    include_dir = os.path.join(src_dir, "include")
    scan_dirs = []
    if os.path.isdir(include_dir):
        scan_dirs.append(include_dir)
    # 顶层 .h（部分项目公开 header 在根目录）
    scan_dirs.append(src_dir)

    for scan_root in scan_dirs:
        is_include = (scan_root == include_dir)
        for root, dirs, files in os.walk(scan_root):
            dirs[:] = [d for d in dirs if d not in {'.git', 'build', 'CMakeFiles', '_deps'}]
            for f in files:
                if not (f.endswith('.h') or f.endswith('.hpp')):
                    continue
                hpath = os.path.join(root, f)
                rel = os.path.relpath(hpath, src_dir)
                # 跳过内部子目录（blosc/、plugins/ 等非公开路径）
                if rel.startswith("blosc/") or rel.startswith("plugins/") or rel.startswith("internal/"):
                    continue
                try:
                    content = open(hpath, 'r', errors='ignore').read()
                except Exception:
                    continue
                for name in api_names:
                    if name in api_to_header:
                        continue
                    if re.search(rf'\b{re.escape(name)}\s*\(', content):
                        # 去掉 include/ 前缀，得到可 include 的路径
                        if is_include and rel.startswith("include/"):
                            api_to_header[name] = rel[len("include/"):]
                        else:
                            api_to_header[name] = rel
    return api_to_header


def extract_helper_signatures(fuzzing_headers_data):
    """从 fuzzing_headers.json 的 content_preview 中提取函数声明和宏定义。"""
    result = {}
    all_headers = (
        fuzzing_headers_data.get("required_headers", []) +
        fuzzing_headers_data.get("optional_headers", [])
    )
    stats = {h["header"]: h for h in fuzzing_headers_data.get("header_stats", [])}

    for h in all_headers:
        hpath = h.get("path", "")
        hname = Path(hpath).name
        stat = stats.get(hname, {})
        preview = stat.get("content_preview", "")
        if not preview:
            continue

        sigs = []
        lines = preview.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()

            # 函数声明: 返回类型 + 函数名 + ( ，排除定义体和注释
            if (re.match(r'^(?:(?:const|unsigned|signed|struct|enum|extern|static|inline|FUZZ_STATIC)\s+)*'
                         r'(?:void|int|unsigned|size_t|uint\d+_t|int\d+_t|char|float|double|'
                         r'[A-Z]\w*)'
                         r'[\s*]+'
                         r'\w+\s*\(', line)
                and not line.startswith('#')
                and not line.startswith('//')
                and not line.startswith('/*')
                and '{' not in line
                and 'LLVMFuzzerTestOneInput' not in line):
                full = line
                j = i + 1
                while j < len(lines) and ';' not in full and j < i + 5:
                    full += ' ' + lines[j].strip()
                    j += 1
                if ';' in full:
                    full = full[:full.index(';') + 1]
                full = re.sub(r'\s+', ' ', full).strip()
                sigs.append(full)

            # #define 宏（单行，有参数或常量）
            elif line.startswith('#define ') and '\\' not in line:
                macro = line
                if '(' in macro or re.match(r'#define\s+[A-Z_]+\s+\S', macro):
                    sigs.append(macro)

            # 多行宏：只提取名称和参数列表（不展开完整定义）
            elif line.startswith('#define ') and '\\' in line and '(' in line:
                macro_head = line.rstrip('\\').strip()
                parts = macro_head.split(None, 2)
                if len(parts) >= 2:
                    name_part = parts[1]
                    if '(' in name_part:
                        paren_end = name_part.index(')') + 1 if ')' in name_part else len(name_part)
                        sigs.append(f"#define {name_part[:paren_end]} ...")

            # typedef
            elif line.startswith('typedef ') and ';' in line:
                sigs.append(line)

            i += 1

        if sigs:
            # 去重（条件编译分支可能产生同名宏）
            seen = set()
            deduped = []
            for s in sigs:
                if s.startswith('#define'):
                    parts = s.split(None, 2)
                    key = parts[1].split('(')[0] if len(parts) > 1 else s
                else:
                    key = s
                if key not in seen:
                    seen.add(key)
                    deduped.append(s)
            result[hname] = deduped

    return result


def format_constants_section(cache, api_names, max_items=30):
    """格式化常量/枚举/typedef 段落，筛选与目标 API 相关的"""
    lines = []
    enums = cache.get("enums", {})
    typedefs = cache.get("typedefs", {})
    constants = cache.get("constants", {})

    # 找到 API 签名中出现的类型名
    funcs = cache.get("functions", cache)
    relevant_types = set()
    for name in api_names:
        if name in funcs:
            sig = funcs[name]
            for word in re.findall(r'\b([A-Z]\w*(?:_t|Type|Ptr|[A-Z]{2,}\w*))\b', sig):
                relevant_types.add(word)

    if enums:
        # 筛选与目标 API 相关的枚举
        shown = []
        for e_name, e_vals in sorted(enums.items()):
            if any(t in e_name for t in relevant_types) or any(
                name.lower() in e_name.lower() for name in api_names
            ):
                shown.append(f"- `enum {e_name}`: {e_vals}")
        if shown:
            lines.append("## 可用枚举类型")
            lines.extend(shown[:60])  # 让 LLM 看到可用类型全集
            lines.append("")

    if typedefs:
        shown = []
        for t_name, t_orig in sorted(typedefs.items()):
            if any(r.lower() in t_name.lower() for r in relevant_types) or \
               any(name.split('_')[0].lower() in t_name.lower() for name in api_names):
                shown.append(f"- `{t_name}` → `{t_orig}`")
        if shown:
            lines.append("## 可用类型别名 (typedef)")
            lines.extend(shown[:60])  # 让 LLM 看到可用类型全集
            lines.append("")

    if constants:
        shown = []
        # 用项目前缀过滤
        project_prefixes = set()
        for name in api_names:
            parts = name.split('_')
            if parts:
                project_prefixes.add(parts[0].upper())
        for c_name, c_val in sorted(constants.items()):
            if any(c_name.startswith(pf) for pf in project_prefixes):
                shown.append(f"- `{c_name}` = {c_val}")
            if len(shown) >= max_items:
                break
        if shown:
            lines.append("## 可用常量 (#define)")
            lines.extend(shown)
            lines.append("")

    return "\n".join(lines)


# ─── Phase B: API 调用序列设计 ─────────────────────────────────────

# 单个 driver 的 API 调用序列长度约束（不再用固定公式，由设计阶段自主决定）
MAX_APIS = 20   # 硬上限：一个 domain 的 API 超过此数才截断，否则全纳入
MIN_APIS = 5    # 软下限：domain 太小时从其他 domain 补足到此数，避免过短 driver


DOMAIN_PREFIX_RULES = [
    ("schunk",    ["blosc2_schunk"]),
    ("frame",     ["blosc2_frame", "frame_"]),
    ("b2nd",      ["b2nd"]),
    ("cbuffer",   ["blosc1_cbuffer", "blosc2_cbuffer"]),
    ("compress",  ["blosc2_compress", "blosc1_compress"]),
    ("decompress",["blosc2_decompress", "blosc1_decompress"]),
    ("stune",     ["blosc_stune"]),
    ("pthread",   ["blosc2_pthread"]),
    ("blosclz",   ["blosclz"]),
    ("bitshuffle",["bshuf", "bitshuffle"]),
    ("set",       ["blosc2_set", "blosc1_set"]),
    ("init",      ["blosc2_init", "blosc1_init"]),
    ("destroy",   ["blosc2_destroy", "blosc1_destroy"]),
]


# ─── 领域预分配（并行支持）────────────────────────────────────

def _sig_names(sig_cache):
    """兼容新旧 sig_cache 格式: 扁平 dict 或嵌套 {'functions': {...}} """
    if isinstance(sig_cache, dict) and "functions" in sig_cache:
        return sig_cache["functions"]
    return sig_cache


C_KW = {'if','for','while','switch','return','sizeof','void','int','char',
        'const','static','unsigned','signed','long','short','double','float',
        'goto','break','continue','case','default','struct','union','enum','typedef',
        'PREFIX','ARRAY_SIZE','Z_UNUSED','MIN','MAX'}


# ─── Phase C: LLM 生成 ─────────────────────────────────────────────

def find_usage_examples(project, api_names, max_snippets=8, lang='c'):
    """从源码树已有 fuzz driver 中提取目标 API 的正确用法示例

    优先顺序: src/<project>/fuzz/ → src/<project>/tests/fuzz/ → projects/<project>/
    源码树中的 driver 保证与当前库版本兼容。

    lang: 目标 driver 语言。'c' 时把 C++ 示例里的 FuzzedDataProvider 阉割成注释；
          'cpp' 时保留原样（C++ 项目应照 C++ 惯用法生成）。
    """
    from config import PROJECTS_DIR
    src_proj = SRC_DIR / project

    # 按优先级排序的搜索目录（projects/ 优先，因为是人工精选的高质量示例）
    search_dirs = []
    for candidate in [
        PROJECTS_DIR / project,
        src_proj / "fuzz",
        src_proj / "tests" / "fuzz",
        src_proj / "ossfuzz",
    ]:
        if candidate.exists():
            search_dirs.append(candidate)

    if not search_dirs:
        return []

    snippets = []
    # C 文件优先，C++ 兜底
    c_files = []
    cpp_files = []
    for d in search_dirs:
        c_files.extend(sorted(d.glob("*.c"), key=lambda p: p.stat().st_size, reverse=True))
        cpp_files.extend(sorted(d.glob("*.cpp"), key=lambda p: p.stat().st_size, reverse=True))
        cpp_files.extend(sorted(d.glob("*.cc"), key=lambda p: p.stat().st_size, reverse=True))
        cpp_files.extend(sorted(d.glob("*.cxx"), key=lambda p: p.stat().st_size, reverse=True))
    # 去重（按文件名）
    seen_names = set()
    all_files = []
    for cf in c_files + cpp_files:
        if cf.name not in seen_names and "standalone" not in cf.name.lower():
            seen_names.add(cf.name)
            all_files.append(cf)

    for cf in all_files[:20]:
        try:
            code = cf.read_text(errors='ignore')
        except Exception:
            continue
        lines = code.splitlines()
        is_cpp = cf.suffix in ['.cpp', '.cc', '.cxx']
        for api in api_names:
            if api not in code:
                continue
            for i, line in enumerate(lines):
                if api + '(' in line or api + ' (' in line:
                    start = max(0, i - 5)
                    end = min(len(lines), i + 10)
                    snippet = '\n'.join(lines[start:end])
                    if is_cpp and lang == 'c':
                        # 仅当目标是 C 项目时，才把 C++ 参考里的 FuzzedDataProvider 阉割成注释。
                        # C++ 项目保留原样，让 LLM 照 C++ 惯用法生成。
                        snippet = snippet.replace('fuzzed_data.Consume',
                                                  '/* C: 用 data[] 代替 */ // was: fuzzed_data.Consume')
                        snippet = snippet.replace('FuzzedDataProvider',
                                                  '/* C: 直接用 data+size */ // was: FuzzedDataProvider')
                    # 标记来源目录（源码树 vs projects）
                    source_tag = ""
                    if str(src_proj) in str(cf):
                        source_tag = " [源码树]"
                    snippets.append({
                        'api': api,
                        'file': cf.name,
                        'is_cpp': is_cpp,
                        'code': snippet,
                        'source_tag': source_tag,
                    })
                    break
            if len(snippets) >= max_snippets:
                break
        if len(snippets) >= max_snippets:
            break

    return snippets[:max_snippets]


def load_project_role_distribution(project):
    """从 _shared/role_labels.jsonl 加载本项目 API 角色分布 {role: [api...]}"""
    labels_path = INTERMEDIATE_DIR / "_shared" / "role_labels.jsonl"
    if not labels_path.exists():
        return {}
    dist = {}
    try:
        for line in labels_path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("project") != project:
                continue
            role = rec.get("role", "unknown")
            dist.setdefault(role, []).append(rec.get("api", ""))
    except Exception:
        pass
    return dist


def load_skeleton_source_info(skeleton_id):
    """从 _shared/skeletons.json 取骨架来源场景信息"""
    skel_path = INTERMEDIATE_DIR / "_shared" / "skeletons.json"
    if not skel_path.exists():
        return {}
    try:
        data = json.loads(skel_path.read_text())
        for sk in data.get("skeletons", []):
            if sk.get("id") == skeleton_id:
                return {
                    "sequence": sk.get("sequence", []),
                    "support_drivers": sk.get("support_drivers", 0),
                    "support_projects": sk.get("support_projects", []),
                    "scenarios": sk.get("scenarios", {}),
                    "scenario_confidence": sk.get("scenario_confidence", ""),
                    "slot_multiplicity": sk.get("slot_multiplicity", {}),
                }
    except Exception:
        pass
    return {}


def _find_complete_driver_examples(project, lang):
    """从 projects/ 目录提取 1-2 个完整的 driver 代码作为参考模板

    归属校验 + 按 API 调用数降序：提取文件调用的函数名，与该项目 scored.json 的
    API 池求交（先剔 libc/通用名黑名单），交集 ≥3 或 ≥50% 才采用。全部不达标不给范例。
    避免优先挑中小文件（standalone runner / fuzz_main.c 等污染文件）。
    """
    from config import PROJECTS_DIR
    proj_dir = PROJECTS_DIR / project
    if not proj_dir.exists():
        return []

    # 加载该项目 API 池（scored.json 的 scored_apis）
    project_apis = set()
    try:
        scored = json.loads((INTERMEDIATE_DIR / project / "scored.json").read_text())
        project_apis = {a["api"] for a in scored.get("scored_apis", []) if a.get("api")}
    except Exception:
        pass

    # libc/通用名黑名单（剔除后求交，防 calloc/memcmp 蒙混）
    libc_blacklist = _STDLIB_C | {"main", "exit", "abort", "return", "if", "for", "while", "switch"}

    # 提取文件调用的函数名（ident( 模式）
    call_re = re.compile(r'\b([A-Za-z_]\w*)\s*\(')

    if lang == 'cpp':
        candidates = list(proj_dir.glob("*.cc")) + list(proj_dir.glob("*.cpp")) + list(proj_dir.glob("*.cxx"))
    else:
        candidates = list(proj_dir.glob("*.c"))

    if not candidates:
        return []

    # 按本项目 API 调用数降序（不是文件大小升序）
    scored_candidates = []
    for cf in candidates:
        try:
            code = cf.read_text(errors='ignore')
            lines = len(code.splitlines())
            if lines > 500:
                continue
            calls = set(call_re.findall(code)) - libc_blacklist
            hit_apis = calls & project_apis
            # 归属校验：交集 ≥3 或占可识别调用 ≥50%
            if len(hit_apis) < 3 and (len(calls) == 0 or len(hit_apis) / len(calls) < 0.5):
                continue
            scored_candidates.append((cf, code, lines, len(hit_apis)))
        except Exception:
            continue

    if not scored_candidates:
        print(f"  [examples] {project}: 无通过归属校验的范例文件（全部丢弃）")
        return []

    # 按 hit_apis 降序取前 2
    scored_candidates.sort(key=lambda x: -x[3])
    examples = []
    for cf, code, lines, hit in scored_candidates[:2]:
        examples.append({
            'file': cf.name,
            'code': code,
            'lines': lines,
            'lang': 'cpp' if cf.suffix in ['.cc', '.cpp', '.cxx'] else 'c',
        })
    return examples


def extract_project_version(src_dir):
    """从源码树提取版本号 + API 前缀，用于 prompt 约束"""
    src = Path(src_dir)
    result = {"version": None, "api_prefix": None, "warnings": []}

    # 1. VERSION 文件
    ver_file = src / "VERSION"
    if ver_file.exists():
        result["version"] = ver_file.read_text().strip()

    # 2. configure.ac
    if not result["version"]:
        for ac_name in ["configure.ac", "configure.in"]:
            ac = src / ac_name
            if ac.exists():
                m = re.search(r'AC_INIT\s*\(\s*\[?[^,\]]+\]?\s*,\s*\[?([^\],]+)\]?',
                              ac.read_text(errors='ignore'))
                if m:
                    result["version"] = m.group(1).strip()
                break

    # 3. CMakeLists.txt: project(VERSION ...)
    if not result["version"]:
        cm = src / "CMakeLists.txt"
        if cm.exists():
            content = cm.read_text(errors='ignore')
            m = re.search(r'project\s*\([^)]*VERSION\s+([^\s)]+)', content)
            if m:
                result["version"] = m.group(1).strip()
            else:
                # 从 include 头文件中查找 VERSION_STRING
                inc_dir = src / "include"
                if inc_dir.exists():
                    for root, _, files in os.walk(inc_dir):
                        for f in files:
                            if not f.endswith('.h'):
                                continue
                            hpath = os.path.join(root, f)
                            try:
                                hc = open(hpath, 'r', errors='ignore').read()
                            except Exception:
                                continue
                            for pfx in ['', 'BLOSC2_', 'BLOSC_', 'LIBXML_', 'NDPI_']:
                                m = re.search(
                                    rf'#define\s+{pfx}VERSION_STRING\s+"([^"]+)"',
                                    hc
                                )
                                if m:
                                    result["version"] = m.group(1)
                                    if not result["api_prefix"]:
                                        result["api_prefix"] = pfx.rstrip("_")
                                    break
                            if result["version"]:
                                break
                        if result["version"]:
                            break

    if not result["version"]:
        result["version"] = "unknown"

    # 推导 API 前缀
    if not result["api_prefix"]:
        # 从项目名推断: c-blosc2 → blosc2, libxml2 → xml
        proj_name = src.name
        known_prefixes = {
            "c-blosc2": ("blosc2", ["blosc1_", "BLOSC1_"]),
            "libxml2": ("xml", []),
            "ndpi": ("ndpi", []),
        }
        # strip leading numbers/symbols and map
        clean = proj_name.lstrip("c-").replace("-", "_")
        banned = []
        for kn, (pfx, ban) in known_prefixes.items():
            if kn in proj_name or proj_name in kn:
                result["api_prefix"] = pfx
                banned = ban
                break
        if not result["api_prefix"]:
            result["api_prefix"] = clean
        result["warnings"] = banned

    return result


def build_version_section(src_dir):
    """构建版本约束段落"""
    info = extract_project_version(str(src_dir))
    lines = [f"## 目标库版本\n- **版本**: {info['version']}"]
    if info["api_prefix"]:
        lines.append(f"- **API 前缀**: 所有公开 API 前缀为 `{info['api_prefix']}_`")
    if info["warnings"]:
        lines.append(f"- **【注意】禁止使用旧版 API**: {', '.join(f'`{w}*`' for w in info['warnings'])}")
    lines.append(f"- **只使用源码树中实际存在的 API**，禁止编造不存在的函数名或头文件路径")
    return "\n".join(lines)


def build_template_section(template_data):
    """构造模板信息段落"""
    if not template_data or template_data.get("num_drivers_analyzed", 0) == 0:
        return """## harness 模板（通用）
- 业务模式: 通用 libFuzzer
- 数据消费策略: direct（直接透传输入字节到 API）
- 无现有模板可参考，请按标准 libFuzzer 模式构造"""

    strategy = template_data.get("dominant_strategy", "direct")
    pattern = template_data.get("dominant_pattern", "unknown")
    init_calls = template_data.get("init_patterns", [])
    business_calls = template_data.get("business_patterns", [])
    verify_calls = template_data.get("verify_patterns", [])
    cleanup_calls = template_data.get("cleanup_patterns", [])
    data_flows = template_data.get("data_flows", [])
    common_includes = template_data.get("common_includes", [])
    num_drivers = template_data.get("num_drivers_analyzed", 0)
    source_type = template_data.get("source_type", "unknown")
    median_size = template_data.get("median_input_size", None)
    class_sources = template_data.get("classification_sources", [])

    strategy_desc = {
        "direct": "直接将输入字节透传给 API（适合 parse/load 类 API）",
        "byte-sliced": "用 data 的前几个字节控制参数（如压缩级别），剩余字节作 payload",
        "producer": "用 FUZZ_dataProducer 抽象分割参数区和 payload 区",
        "tlv": "用 TLV 结构编码 API 操作序列",
    }.get(strategy, "标准 libFuzzer 模式")

    pattern_desc = {
        "round_trip": "compress→decompress 或 encode→decode 往返验证",
        "parse_only": "直接 parse/load 输入字节，验证解析器鲁棒性",
        "streaming": "分块处理输入字节",
        "multi_api": "多 API 组合调用",
        "state_machine": "有状态机/协议解析",
    }.get(pattern, f"通用模式")

    source_desc = {
        "own_project": f"从该项目 {num_drivers} 个已有 harness 提取",
        "peer_project": f"从同类项目 {num_drivers} 个 harness 提取",
        "generic": "通用模板",
    }.get(source_type, "")

    from collections import Counter
    src_summary = ""
    if class_sources:
        src_counts = Counter(class_sources)
        src_parts = []
        for src, cnt in src_counts.items():
            label = "Agent" if src == "agent" else "Regex"
            src_parts.append(f"{cnt}个{label}")
        src_summary = f" ({', '.join(src_parts)})"

    lines = [
        "## harness 模板（从已有 harness 提取" + src_summary + "）",
        f"- **来源**: {source_desc}",
        f"- **业务模式**: {pattern} — {pattern_desc}",
        f"- **数据消费策略**: {strategy} — {strategy_desc}",
    ]

    if common_includes:
        inc_str = ", ".join(f"`{h}`" for h in common_includes[:10])
        lines.append(f"- **公共头文件**: {inc_str}")

    if init_calls:
        init_str = ", ".join(f"`{c}()`" for c in init_calls[:5])
        lines.append(f"- **初始化函数**: {init_str}")

    if business_calls:
        biz_str = ", ".join(f"`{c}()`" for c in business_calls[:8])
        lines.append(f"- **业务 API**: {biz_str}")

    if verify_calls:
        ver_str = ", ".join(f"`{c}()`" for c in verify_calls[:5])
        lines.append(f"- **验证 API**: {ver_str}")

    if cleanup_calls:
        cl_str = ", ".join(f"`{c}()`" for c in cleanup_calls[:5])
        lines.append(f"- **清理函数**: {cl_str}")

    if data_flows:
        lines.append(f"- **数据流**:")
        for df in data_flows[:5]:
            lines.append(f"  - `{df.get('from_api', '?')}()` → `{df.get('to_api', '?')}()`: {df.get('what', '')}")

    if median_size:
        lines.append(f"- **建议最大输入**: {median_size} bytes")

    lines.append("")
    return "\n".join(lines)


def call_openai_compatible_model(prompt, model, api_key, base_url):
    """调用 OpenAI 兼容 API（DeepSeek 等）——使用 requests，无需 openai SDK。"""
    import time
    import requests as _req

    t0 = time.time()
    url = (base_url.rstrip("/") if base_url else "https://api.deepseek.com") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 32768,   # DeepSeek 推理模式：reasoning_content 占大量 token，需留 content 空间
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert C/C++ security engineer specializing in coverage-guided fuzzing and OSS-Fuzz harness development. "
                    "Your task is to generate a production-quality libFuzzer fuzz driver (harness) for an open-source library.\n\n"
                    "A fuzz driver implements `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and feeds the fuzzer-provided "
                    "byte payload into the target library's APIs to maximize code coverage and trigger latent bugs "
                    "(heap-buffer-overflow, use-after-free, integer-overflow, null-dereference, etc.) detectable by "
                    "AddressSanitizer, MemorySanitizer, and UBSan.\n\n"
                    "Requirements:\n"
                    "- Compile cleanly with clang under OSS-Fuzz build flags: -fsanitize=address,fuzzer-no-link\n"
                    "- Exercise the specified API sequence in a realistic call order (init → use → cleanup)\n"
                    "- Handle all error paths: check every pointer return for NULL, every error code for failure\n"
                    "- Free all allocated resources on every exit path to avoid false-positive leak reports\n"
                    "- Never call exit() or abort(); return 0 on all paths\n\n"
                    "Output only the complete C/C++ source code in a single fenced code block. No prose, no explanation."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = _req.post(url, json=payload, headers=headers, timeout=180)
        elapsed = time.time() - t0
        if resp.status_code != 200:
            print(f"    [{model}] API HTTP {resp.status_code} ({elapsed:.1f}s): {resp.text[:200]}", flush=True)
            return None
        data = resp.json()
        msg = data.get("choices", [{}])[0].get("message", {})
        # DeepSeek 推理模式：content 空 → 取 reasoning_content 兜底
        text = msg.get("content", "") or msg.get("reasoning_content", "") or ""
        if text:
            print(f"    [{model}] API 成功 ({elapsed:.1f}s, {len(text)} chars"
                  + (", via reasoning_content" if not msg.get("content") else "") + ")", flush=True)
            return text
        print(f"    [{model}] API 空响应 ({elapsed:.1f}s)", flush=True)
        return None
    except Exception as e:
        elapsed = time.time() - t0
        print(f"    [{model}] API 异常 ({elapsed:.1f}s): {type(e).__name__}: {str(e)[:200]}", flush=True)
        return None


def call_llm(prompt, model, api_key, base_url, provider):
    """调用 LLM（当前仅支持 OpenAI 兼容接口）。"""
    return call_openai_compatible_model(prompt, model, api_key, base_url)


def extract_code(response_text):
    """从 LLM 响应中提取 C 代码"""
    m = re.search(r'```c\n(.*?)\n```', response_text, re.DOTALL)
    if not m:
        m = re.search(r'```cpp\n(.*?)\n```', response_text, re.DOTALL)
    if not m:
        m = re.search(r'```\n(.*?)\n```', response_text, re.DOTALL)
    if m:
        return m.group(1).strip()
    if '```c' in response_text or '```cpp' in response_text or '```' in response_text:
        return None
    if 'LLVMFuzzerTestOneInput' in response_text:
        return response_text.strip()
    return None


def is_valid_driver(code):
    """检查生成的 driver 是否完整"""
    if not code or len(code) < 80:
        return False
    if 'LLVMFuzzerTestOneInput' not in code:
        return False
    if '```c' in code or '```cpp' in code or '```' in code:
        return False
    if code.count('{') != code.count('}'):
        return False
    last_lines = code.strip().rsplit('\n', 5)
    last_content = '\n'.join(last_lines)
    if 'return 0' not in last_content and 'return' not in last_content:
        return False
    if code.startswith('{') or code.startswith('```json'):
        return False
    bad_starts = ['here', 'sure', 'i\'ll', 'i will', 'let me', 'below', 'the following']
    first_word = code.strip().split()[0].lower() if code.strip().split() else ''
    if first_word in bad_starts:
        return False
    return True


def _is_private_header(name: str) -> bool:
    """判断一个源码根目录下的 .h 是否是「项目私有/内部头」，不应让 driver 直接 include。

    这类头通常是构建期由 configure/cmake 生成、依赖 HAVE_* 宏或内部编译单元上下文，
    外部单独 include 会触发 `#error`（如 json-c 的 vasprintf_compat.h/snprintf_compat.h
    顶部 `#error snprintf is required but was not found`）或暴露不该用的内部符号。

    仅用通用命名约定（不针对任何具体项目），宁可漏判（放行）不误伤公开 API 头：
      - *_compat.h / *_internal.h / *_private.h / *_priv.h  → 私有
      - config.h / *config.h / *_config.h                  → 构建期生成配置头
    公开 umbrella header（如 json.h）与项目名同名头一律不受影响。
    """
    stem = name[:-2] if name.endswith(".h") else name
    stem = stem.lower()
    for suf in ("_compat", "_internal", "_private", "_priv", "_impl"):
        if stem.endswith(suf):
            return True
    if stem == "config" or stem.endswith("config"):
        return True
    return False


def build_include_whitelist(project):
    """从 fuzzing_headers.json + 标准库构建 include 白名单。"""
    allowed = set()
    fh_path = INTERMEDIATE_DIR / project / "fuzzing_headers.json"
    if fh_path.exists():
        try:
            fh_data = json.loads(fh_path.read_text())
            for h in fh_data.get("required_headers", []):
                allowed.add(Path(h["path"]).name)
            for h in fh_data.get("optional_headers", []):
                allowed.add(Path(h["path"]).name)
            for h in fh_data.get("standard_or_api_headers", []):
                allowed.add(Path(h).name)
        except Exception:
            pass

    src_inc = SRC_DIR / project / "include"
    if src_inc.exists():
        for f in src_inc.rglob("*.h"):
            allowed.add(f.name)
    src_root = SRC_DIR / project
    if src_root.exists():
        for f in src_root.glob("*.h"):
            if _is_private_header(f.name):
                continue
            allowed.add(f.name)

    allowed.update([
        "stddef.h", "stdint.h", "stdlib.h", "stdio.h", "string.h",
        "stdbool.h", "time.h", "limits.h", "assert.h", "math.h",
        "errno.h", "float.h", "inttypes.h", "signal.h", "unistd.h",
        "fcntl.h", "sys/types.h", "sys/stat.h", "memory.h", "setjmp.h",
        "stdarg.h",  # 可变参数（va_list/va_start/va_end）
        "cstring", "cstdlib", "cstdio", "cstdint", "cassert", "climits",
        "cmath", "cstddef", "iostream", "fstream", "sstream", "vector",
        "string", "memory", "algorithm", "functional", "map", "set",
        "unordered_map", "unordered_set", "array", "ctime", "cerrno",
        "csetjmp", "csignal", "numeric", "iterator", "utility", "tuple",
        "cstdarg",  # C++ 可变参数
        "fuzzer/FuzzedDataProvider.h", "FuzzedDataProvider.h",  # libFuzzer 标准 C++ helper
    ])
    return allowed


def validate_driver_includes(code, project):
    """检查 driver 代码的 #include 是否都在白名单内。"""
    whitelist = build_include_whitelist(project)
    if not whitelist:
        return True, []

    violations = []
    for line in code.splitlines():
        line = line.strip()
        m = re.match(r'^\s*#include\s+[<"]([^>"]+)[>"]', line)
        if not m:
            continue
        header = m.group(1)
        basename = Path(header).name
        if basename not in whitelist and header not in whitelist:
            violations.append(header)
    return len(violations) == 0, violations


# ─── Block B: 函数调用硬验证器 ─────────────────────────────────────

_STDLIB_C = {
    'memcpy','memmove','memcmp','memset','memchr','memmem',
    'strcmp','strncmp','strcasecmp','strncasecmp','strlen','strnlen',
    'strdup','strndup','strchr','strrchr','strstr','strspn','strcspn',
    'strpbrk','strtok','strtok_r','strcpy','strncpy','strcat','strncat',
    'strerror','strerror_r','strsignal',
    'malloc','calloc','realloc','free','aligned_alloc','posix_memalign',
    'printf','fprintf','sprintf','snprintf','asprintf','vprintf','vfprintf',
    'vsprintf','vsnprintf','fputs','fputc','putchar','puts',
    'scanf','fscanf','sscanf','vscanf','vfscanf','vsscanf',
    'fgets','fgetc','getchar','gets','ungetc',
    'fread','fwrite','fopen','freopen','fclose','fflush','fseek','ftell',
    'rewind','fseeko','ftello','fileno','feof','ferror','clearerr','setvbuf',
    'abort','exit','_Exit','atexit','abort','raise','signal','kill',
    'atoi','atol','atoll','atof','strtol','strtoll','strtoul','strtoull',
    'strtof','strtod','strtold',
    'abs','labs','llabs','div','ldiv','lldiv',
    'qsort','bsearch','rand','srand',
    'pow','sqrt','cbrt','exp','log','log2','log10','sin','cos','tan',
    'asin','acos','atan','atan2','sinh','cosh','tanh',
    'floor','ceil','round','trunc','fmod','fabs','fmax','fmin','hypot',
    'isnan','isinf','isfinite','isnormal',
    'isdigit','isalpha','isalnum','isspace','isprint','iscntrl','ispunct',
    'isupper','islower','isxdigit','isascii',
    'tolower','toupper',
    'time','clock','gettimeofday','difftime','mktime','localtime','gmtime',
    'strftime','strptime','asctime','ctime',
    'getenv','setenv','unsetenv','putenv','system','getpid','getppid',
    'geteuid','getuid','getegid','getgid','getcwd','chdir',
    'read','write','close','open','openat','creat','pread','pwrite',
    'lseek','fcntl','ioctl','dup','dup2','pipe','poll','select',
    'mmap','munmap','mprotect','madvise','msync','mlock','munlock','brk','sbrk',
    'stat','fstat','lstat','access','chmod','chown','umask','unlink','rename',
    'mkdir','rmdir','symlink','readlink','link',
    'setjmp','longjmp','sigsetjmp','siglongjmp',
    'assert','__assert_fail',
    'errno','strerror',
    'getopt','getopt_long',
    # 临时文件/目录（fuzz driver 常用：写数据到临时文件再读）
    'mkstemp','mkstemps','mkdtemp','mkostemp','mkostemps',
    'tmpfile','tmpnam','tempnam','tmpfile64','tmpnam_r',
    # 栈分配 / 字符串扩展（BSD/glibc 常用）
    'alloca','strdupa','strndupa','strlcpy','strlcat','memccpy',
    'stpcpy','stpncpy','strcasestr','strsep','strchrnul','strnlen',
    'basename','dirname',
    # 进程 / 信号
    'fork','vfork','_exit','waitpid','wait','waitid','wait4',
    'execl','execlp','execv','execvp','execve','execlpe','execvpe',
    'sigaction','sigemptyset','sigfillset','sigaddset','sigdelset',
    'sigprocmask','sigpending','sigsuspend','sigwait','sigwaitinfo',
    'killpg','setpgid','getpgid','setsid','getsid','prctl',
    # 时间 / 睡眠
    'clock_gettime','clock_settime','clock_nanosleep','nanosleep','sleep','usleep',
    # 目录流
    'opendir','readdir','readdir_r','closedir','rewinddir','telldir','seekdir',
    'scandir','alphasort','dirfd',
    # IO 补充
    'perror','dprintf','vdprintf','getline','getdelim','popen','pclose',
    'fdatasync','fsync','flock','fileno',
    # 路径
    'realpath','canonicalize_file_name',
    # 用户/组
    'getpwuid','getpwnam','getgrgid','getgrnam','getlogin','getlogin_r',
    # 终端
    'isatty','ttyname','ttyname_r','ctermid','tcgetattr','tcsetattr',
    # 宽字符（部分 driver 用）
    'wprintf','wscanf','fwprintf','fwscanf','swprintf','swscanf',
    'wcslen','wcscpy','wcsncpy','wcscat','wcsncat','wcscmp','wcsncmp',
    'wcschr','wcsrchr','wcsstr','wcstombs','mbstowcs','wctomb','mbtowc',
    'btowc','wctob',
    # 大文件 / off_t
    'fopen64','freopen64','fseeko64','ftello64','stat64','fstat64','lstat64',
    'open64','creat64','lseek64','mmap64','pread64','pwrite64',
    # 杂项常用
    'htonl','htons','ntohl','ntohs','be32toh','be16toh','le32toh','le16toh',
    'inet_pton','inet_ntop','inet_addr','inet_ntoa',
    'getaddrinfo','freeaddrinfo','getnameinfo','socket','connect','bind',
    'listen','accept','send','recv','sendto','recvfrom','sendmsg','recvmsg',
    'shutdown','setsockopt','getsockopt','getsockname','getpeername',
}
_STDLIB_CPP = {
    'push_back','emplace_back','pop_back','push_front','emplace_front','pop_front',
    'begin','end','cbegin','cend','rbegin','rend','crbegin','crend',
    'size','length','empty','max_size','capacity','reserve','resize','shrink_to_fit',
    'clear','insert','emplace','emplace_hint','erase','swap','assign',
    'front','back','at','data','c_str',
    'find','count','contains','lower_bound','upper_bound','equal_range',
    'substr','append','compare','starts_with','ends_with','replace',
    'move','forward','make_pair','make_shared','make_unique','make_tuple',
    'get','tie','ignore',
    'to_string','stoi','stol','stoll','stoul','stoull','stof','stod',
    'sort','stable_sort','partial_sort','nth_element','partition',
    'copy','copy_n','copy_if','move_backward','fill','fill_n','generate',
    'transform','for_each','accumulate','reduce','partial_sum',
    'min','max','minmax','clamp','all_of','any_of','none_of','equal',
    'lexicographical_compare','includes','set_difference','set_intersection',
    'set_union','merge',
    'unique','remove','remove_if','reverse','rotate','shuffle',
    'lock','unlock','try_lock','lock_guard','unique_lock','scoped_lock',
}
_BUILTINS_PREFIXES = ('__builtin_', '__sync_', '__atomic_')
_BUILTINS = {
    'sizeof','alignof','offsetof','typeof','__typeof__','defined',
    'static_assert','_Static_assert','_Alignas','_Alignof','_Generic',
    'asm','__asm__','__attribute__','__extension__','__inline__','__restrict__',
    '_Pragma','__PRETTY_FUNCTION__','__func__','__FUNCTION__',
    'va_start','va_end','va_arg','va_copy',
    'setjmp','longjmp',
}
_DECL_KW = {
    'extern','namespace','template','struct','union','class','enum','typedef',
    'case','catch','throw','new','delete','goto','using','operator',
    'public','private','protected','virtual','override','final','explicit',
    'friend','mutable','volatile','constexpr','constinit','consteval',
    'noexcept','decltype','nullptr','true','false','this',
}

# Platform-specific headers (OSS-Fuzz only supports Linux/POSIX)
_PLATFORM_SPECIFIC_HEADERS = {
    'windows/': 'Windows-specific path',
    'win32/': 'Windows-specific path',
    '<crtdefs.h>': 'MSVC-specific header (Windows)',
    '<windows.h>': 'Windows API header',
    '<winbase.h>': 'Windows API header',
    '<windef.h>': 'Windows API header',
    '<io.h>': 'MSVC I/O header (use <unistd.h> on Linux)',
    '<direct.h>': 'MSVC directory header (use <unistd.h> on Linux)',
}


def _strip_noncode(code):
    """状态机剥离行/块注释、字符串/字符字面量，用空格保留行号。"""
    out = []
    i, n = 0, len(code)
    state = 'code'  # 'code' | 'line_comment' | 'block_comment' | 'string' | 'char'
    while i < n:
        c = code[i]
        nxt = code[i+1] if i+1 < n else ''
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
                out.append(' ' if c != '\t' else '\t')
            i += 1; continue
        if state == 'block_comment':
            if c == '*' and nxt == '/':
                out.append('  '); state = 'code'; i += 2; continue
            out.append('\n' if c == '\n' else (' ' if c != '\t' else '\t'))
            i += 1; continue
        if state == 'string':
            if c == '\\' and nxt:
                out.append('  '); i += 2; continue
            if c == '"':
                out.append(' '); state = 'code'; i += 1; continue
            out.append('\n' if c == '\n' else ' ')
            i += 1; continue
        if state == 'char':
            if c == '\\' and nxt:
                out.append('  '); i += 2; continue
            if c == "'":
                out.append(' '); state = 'code'; i += 1; continue
            out.append('\n' if c == '\n' else ' ')
            i += 1; continue
    return ''.join(out)


def build_call_whitelist(project, sig_cache, fh_data):
    """构建函数调用白名单和黑名单。

    Returns:
        (allowed: set[str], blacklisted: set[str], helper_macros: set[str])
    """
    allowed = set()

    # 1. sig_cache 里的所有函数名（headers 全扫的超集）
    sig_funcs = _sig_names(sig_cache)
    if isinstance(sig_funcs, dict):
        allowed |= set(sig_funcs.keys())
    else:
        allowed |= set(sig_funcs)

    # 2. scored.json 的项目 API
    scored_path = INTERMEDIATE_DIR / project / "scored.json"
    if scored_path.exists():
        try:
            scored = json.loads(scored_path.read_text())
            for item in scored.get("scored_apis", []):
                allowed.add(item["api"])
        except Exception:
            pass

    # 3. Helper 函数/宏（从 fuzzing_headers.json content_preview 提取）
    helper_macros = set()
    if fh_data:
        helper_sigs = extract_helper_signatures(fh_data)
        for hname, sigs in helper_sigs.items():
            for s in sigs:
                # 提取所有可能的名字：先抓 #define / typedef，再抓函数
                m = re.match(r'^#define\s+([A-Za-z_]\w*)', s)
                if m:
                    allowed.add(m.group(1))
                    helper_macros.add(m.group(1))
                    continue
                m = re.match(r'^typedef\s+.*?\b([A-Za-z_]\w*)\s*;?\s*$', s)
                if m:
                    allowed.add(m.group(1))
                    continue
                # 函数：抓 `name(` 前的最后一个 identifier
                for fm in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', s):
                    allowed.add(fm.group(1))

    # 4. 内置集
    allowed |= _STDLIB_C
    allowed |= _STDLIB_CPP
    allowed |= _BUILTINS
    allowed |= _DECL_KW
    allowed |= C_KW

    blacklisted = set()

    return allowed, blacklisted, helper_macros


_CALL_RE = re.compile(r'(?<![\w.>:])([A-Za-z_][A-Za-z_0-9]*)\s*\(')

# 类型使用硬验证 —— 类型可见性（基于 include 传递闭包）
# 匹配两类类型使用：xxx_t 惯例命名 + 显式 struct/union/enum Tag
_TYPE_USE_RE = re.compile(
    r'\b([a-z_][a-z0-9_]*_t)\b'                      # 组1: xxx_t 惯例类型
    r'|(?:struct|union|enum)\s+([A-Za-z_]\w*)'       # 组2: struct/union/enum 标签
)

# C/C++ 标准库类型白名单（永久豁免，不参与可见性验证）
_STDLIB_TYPES = frozenset({
    'size_t', 'ssize_t', 'ptrdiff_t', 'intptr_t', 'uintptr_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int_least8_t', 'int_least16_t', 'int_least32_t', 'int_least64_t',
    'uint_least8_t', 'uint_least16_t', 'uint_least32_t', 'uint_least64_t',
    'int_fast8_t', 'int_fast16_t', 'int_fast32_t', 'int_fast64_t',
    'uint_fast8_t', 'uint_fast16_t', 'uint_fast32_t', 'uint_fast64_t',
    'intmax_t', 'uintmax_t', 'wchar_t', 'char16_t', 'char32_t',
    'wint_t', 'sig_atomic_t', 'time_t', 'clock_t', 'off_t',
    'mode_t', 'pid_t', 'uid_t', 'gid_t', 'fpos_t', 'div_t', 'ldiv_t',
    'va_list', 'jmp_buf', 'sigjmp_buf', 'FILE', 'DIR', 'bool',
    'max_align_t', 'nullptr_t', 'byte',
})


def _reachable_headers(include_graph, entry_headers):
    """从 driver 的 include 集出发，计算项目头文件的传递可达闭包。"""
    seen = set()
    stack = list(entry_headers)
    while stack:
        h = stack.pop()
        if h in seen:
            continue
        seen.add(h)
        for nxt in include_graph.get(h, []):
            if nxt not in seen:
                stack.append(nxt)
    return seen


def validate_driver_types(code, project, sig_cache):
    """硬验证：driver 用的类型必须从其 include 的公开头「传递可达」。

    保守策略（假阳性零容忍）：
      - 只拦「有已知定义头、但该头不在 include 传递闭包内」的类型（高置信）
      - 只查 xxx_t 惯例命名 + 显式 struct/union/enum X
      - 标准库类型豁免；无定义头记录的类型不拦（可能是局部/模板/宏类型）

    Returns:
        (ok: bool, invisible_types: set[str])
    """
    type_headers = sig_cache.get("type_headers", {}) if isinstance(sig_cache, dict) else {}
    include_graph = sig_cache.get("include_graph", {}) if isinstance(sig_cache, dict) else {}
    if not type_headers or not include_graph:
        return True, set()  # 原料缺失，不拦（保守）

    stripped = _strip_noncode(code)

    # driver 自己写的 include（在原始 code 上提取——_strip_noncode 会把 "xxx.h"
    # 当字符串字面量清空，只剩 <> 形式，故必须用原始 code）
    driver_includes = set()
    for m in re.finditer(r'#\s*include\s+[<"]([^>"]+)[>"]', code):
        driver_includes.add(os.path.basename(m.group(1)))

    # 从 driver include 出发算传递闭包
    visible = _reachable_headers(include_graph, driver_includes)

    invisible_types = set()
    for m in _TYPE_USE_RE.finditer(stripped):
        t = m.group(1) or m.group(2)
        if not t or t in _STDLIB_TYPES or t.startswith('__'):
            continue
        defining_header = type_headers.get(t)
        # 只拦：有定义头（真实存在）但不可见（不在闭包）
        if defining_header and defining_header not in visible:
            invisible_types.add(t)

    return (not invisible_types), invisible_types


# libFuzzer 入口/回调函数：driver 自己定义（非调用），validator 永久豁免。
_ENTRY_FUNCS = frozenset({
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
    "LLVMFuzzerCustomMutator",
    "LLVMFuzzerCustomCrossOver",
})


def _load_fh_data(project):
    """加载 fuzzing_headers.json，找不到返回 None。"""
    fh_path = INTERMEDIATE_DIR / project / "fuzzing_headers.json"
    if not fh_path.exists():
        return None
    try:
        return json.loads(fh_path.read_text())
    except Exception:
        return None


def validate_platform_headers(code):
    """检查代码中是否包含平台特定头文件 (OSS-Fuzz 只支持 Linux/POSIX)。

    Returns:
        (ok: bool, violations: list[str])
    """
    violations = []
    for line_no, line in enumerate(code.splitlines(), 1):
        # 只检查 #include 行
        if not re.match(r'^\s*#\s*include', line):
            continue

        for pattern, reason in _PLATFORM_SPECIFIC_HEADERS.items():
            if pattern in line:
                violations.append(f"L{line_no}: {line.strip()} → {reason}")

    return len(violations) == 0, violations


def validate_driver_calls(code, project, sig_cache, fh_data):
    """扫描 driver 里所有 ident( 形式的调用，判定臆造/黑名单。

    Returns:
        (ok: bool, fake_calls: set[str], blacklisted_hits: set[str])
    """
    allowed, blacklisted, helper_macros = build_call_whitelist(project, sig_cache, fh_data)

    stripped = _strip_noncode(code)

    fake_calls = set()
    blk_hits = set()

    for m in _CALL_RE.finditer(stripped):
        ident = m.group(1)
        start = m.start(1)

        # 跳过：语句关键字/内置
        if ident in _BUILTINS or ident in _DECL_KW or ident in C_KW:
            continue
        if ident.startswith(_BUILTINS_PREFIXES):
            continue

        # 跳过：libFuzzer 入口/回调函数（driver 自己定义，非调用；永久豁免）
        if ident in _ENTRY_FUNCS:
            continue

        # 跳过：宏定义左值（当前行 `#define NAME(...)`）
        line_start = stripped.rfind('\n', 0, start) + 1
        line_end = stripped.find('\n', start)
        cur_line = stripped[line_start: line_end if line_end != -1 else len(stripped)].strip()
        if cur_line.startswith('#define ') or cur_line.startswith('#define\t'):
            # 检查是不是"当前 ident 就是被定义的宏名"
            after_define = cur_line[len('#define'):].lstrip()
            if after_define.startswith(ident):
                continue

        # 跳过：函数指针解引用调用 —— 前一非空白字符是 * & (
        p = start - 1
        while p >= 0 and stripped[p] in ' \t':
            p -= 1
        if p >= 0 and stripped[p] in '*&(':
            continue

        # 命中黑名单优先（即使 sig_cache 里有）
        if ident in blacklisted:
            blk_hits.add(ident)
            continue

        # 全大写 helper 宏放行
        if ident.isupper() and ident in helper_macros:
            continue

        # 白名单命中放行
        if ident in allowed:
            continue

        # 都不命中 → 臆造
        fake_calls.add(ident)

    ok = not fake_calls  # 只检查臆造
    return ok, fake_calls, blk_hits


# ─── 编译验证 ──────────────────────────────────────────────────────

# ─── 并行 driver 生成 ────────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════════
# Phase 8: plan 驱动的生成（骨架填槽，替代旧 design_call_sequence 流程）
# ══════════════════════════════════════════════════════════════════════

def build_prompt_from_plan(project, mode, plan_driver, template_data, src_dir):
    """从 plan_<mode>.json 的单个 driver 项构造 prompt（§8.3）——旧 build_prompt 上下文超集。

    在旧 build_prompt 的全部上下文（template/constants/version/fuzzing_headers/
    header_map/usage_examples）基础上，把 sequence_section 换成 plan 骨架槽位。
    范例按 §7.2：focus 给本项目源码 / peer 给同场景源码 / cross 不给。
    """
    skeleton = plan_driver.get("skeleton", [])
    slots = plan_driver.get("slots", [])
    lang = (template_data.get("dominant_lang") or "c")
    ext = "cpp" if lang == "cpp" else "c"
    code_block = "cpp" if lang == "cpp" else "c"
    is_cpp = lang == "cpp"

    # 收集槽位候选 API 名（供 header_map/constants 等复用旧 helper）
    api_names = []
    for s in slots:
        for c in s.get("candidates", []):
            if c.get("api"):
                api_names.append(c["api"])
    api_names = list(dict.fromkeys(api_names))  # 去重保序

    # 签名缓存（供 constants/header_map/types 用）
    sig_cache = build_signature_cache(str(src_dir))
    scored_sigs = load_scored_signatures(project)
    signatures = lookup_signatures(sig_cache, api_names, scored_sigs)
    # KG 富化签名优先：用 _format_scored_sig 格式化（签名 + description），保留用途信息
    scored_data_path = INTERMEDIATE_DIR / project / "scored.json"
    api_meta = {}
    if scored_data_path.exists():
        sd = json.loads(scored_data_path.read_text())
        api_meta = {s["api"]: s for s in sd.get("scored_apis", [])}
        for name in api_names:
            meta = api_meta.get(name)
            if meta and meta.get("signature"):
                signatures[name] = _format_scored_sig(name, meta)

    # ── 1. lang_guide（C/C++ 分支，详细约束，无项目特定示例）──
    if is_cpp:
        lang_guide = f"""你的任务：为 OSS-Fuzz 项目 **{project}** 编写一个 **C++ libFuzzer fuzz driver**（harness），文件后缀 `.{ext}`。

【注意】**关键约束**：本项目的示例 driver 全部是 **C++** 文件，你生成的 driver 也必须是 **C++** 代码。

该 fuzz driver 将在 OSS-Fuzz 的 Docker 构建环境（clang + AddressSanitizer + `LIB_FUZZING_ENGINE=-fsanitize=fuzzer`）中编译，由 libFuzzer coverage-guided fuzzing 持续运行，发现 {project} 的 heap-buffer-overflow、use-after-free、integer-overflow 等内存安全 bug。

## 【注意】C++ 特定要求（严格执行，违反将导致编译失败）

1. **入口函数**: `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`（必须有 `extern "C"` 防 name mangling）

2. **不透明结构体**: 如果 API 接收 `SomeType *`，必须用工厂函数（`SomeType_new()` / `SomeType_create()`）分配，用 `SomeType_free()` / `SomeType_destroy()` 释放；绝不传 nullptr 给不透明指针参数；禁止 `struct xxx var;` 栈分配未知大小类型

3. **参数严格匹配**: 调用任何 API 前必须从 signature 读取确切参数数量和类型，禁止猜测；如示例/签名有 N 个参数，必须传 N 个

4. **goto 安全**: 如用 goto 清理资源，不跨越变量声明作用域；提前声明所有需要的变量

5. **输入数据处理**: 可用 `FuzzedDataProvider`（`#include <fuzzer/FuzzedDataProvider.h>`），或继承项目 Stream/Decoder 类并实现回调，或手动解析 `data` 字节数组

6. **禁止调用内部/测试工具函数**: 只用公开 API；不要 include `oss-fuzz/common.h` 等内部测试头

7. **返回值检查**: 每个返回指针的函数必须检查 nullptr，返回错误码的检查非零值；错误路径必须释放已分配资源后 `return 0`

8. **资源释放**: 所有通过库 API 分配的资源（handle、buffer、context）必须在所有 return 路径上释放，避免 LeakSanitizer 误报

按上方骨架序列顺序构造调用，每槽**只用候选 API**（不要调用候选之外的其他 API）。
每个 API 必须严格按 signature 的参数数量传参——数 signature 括号内的参数个数，
传错数量（too few/many arguments）会导致编译失败。参数从 signature 读取，不要猜。"""
    else:
        lang_guide = f"""你的任务：为 OSS-Fuzz 项目 **{project}** 编写一个 **纯 C libFuzzer fuzz driver**（harness），文件后缀 `.{ext}`。

【注意】**关键约束**：生成的 driver 必须是 **纯 C** 代码，不得使用 C++ 特性。

该 fuzz driver 将在 OSS-Fuzz 的 Docker 构建环境（clang + AddressSanitizer + `LIB_FUZZING_ENGINE=-fsanitize=fuzzer`）中编译，由 libFuzzer coverage-guided fuzzing 持续运行，发现 {project} 的 heap-buffer-overflow、use-after-free、integer-overflow 等内存安全 bug。

## 【注意】C 特定要求

1. **入口函数**: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`

2. **输入切分**: 只能用 `data[i]` 索引 + `size` 边界检查；如需字符串，手动 `memcpy` 后补 `\\0`；不能使用 FuzzedDataProvider

3. **禁止不透明类型栈分配**: 头文件中仅有前向声明（`struct xxx;`）的类型只能用指针操作，必须通过工厂函数分配，禁止 `struct xxx var;` 栈分配

4. **参数数量和类型必须精确**: 调用每个 API 时参数个数、顺序、类型必须与函数签名严格一致，禁止猜测

5. **禁止 C++ 特性**: 不要使用 class、template、namespace、iostream、new/delete、std:: 等

6. **不透明结构体指针**: 如果 API 接收 `SomeType *`，必须先用 `SomeType_new()` / `SomeType_alloc()` 等工厂函数分配后传入；绝不传 NULL 给不透明指针参数

7. **返回值检查**: 每个返回指针的函数必须检查 NULL，返回错误码的函数必须检查非零值；错误路径必须释放已分配资源后 `return 0`

8. **资源释放**: 所有通过库 API 分配的资源（handle、buffer、context）必须在所有 return 路径上释放，避免 LeakSanitizer 误报

按上方骨架序列顺序构造调用，每槽**只用候选 API**（不要调用候选之外的其他 API）。
每个 API 必须严格按 signature 的参数数量传参——数 signature 括号内的参数个数，
传错数量（too few/many arguments）会导致编译失败。参数从 signature 读取，不要猜。"""

    # ── 2. build_info（复用旧逻辑）──
    build_info = ""
    bp_path = INTERMEDIATE_DIR / project / "build_profile.json"
    if bp_path.exists():
        try:
            build_profile = json.loads(bp_path.read_text())
            inc_dirs = build_profile.get("include_dirs", [])
            if inc_dirs:
                build_info += "\n## 构建环境 (include 路径)\n" + "\n".join(f"- {d}" for d in inc_dirs[:8])
            build_info += f"\n**编译器**: {build_profile.get('preferred_compiler', 'clang')}"
            build_info += f"\n**构建系统**: {build_profile.get('build_system', 'unknown')}\n"
        except Exception:
            pass

    # ── 3. header_info（只列公开 header：include/ 目录或顶层 .h，跳过内部子目录）
    header_files = []
    src = Path(src_dir)
    if src.exists():
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d not in {'.git', 'tests', 'test', 'examples', 'bench'}]
            for f in files:
                if f.endswith('.h'):
                    rel = os.path.relpath(os.path.join(root, f), src)
                    # 跳过内部子目录（blosc/、plugins/、internal/ 等）
                    if rel.startswith(("blosc/", "plugins/", "internal/", "private/")):
                        continue
                    # 只保留 include/ 下的或顶层 .h（公开 header）
                    if rel.startswith("include/") or rel.count(os.sep) == 0:
                        clean = rel[len("include/"):] if rel.startswith("include/") else rel
                        header_files.append(clean)
            if len(header_files) > 20:
                break
    header_info = "\n".join(f"- {h}" for h in sorted(set(header_files))[:20])

    # ── 4. fuzzing_headers_section（复用旧逻辑：含 helper API 清单）──
    fuzzing_headers_section = ""
    fh_path = INTERMEDIATE_DIR / project / "fuzzing_headers.json"
    if fh_path.exists():
        try:
            fh_data = json.loads(fh_path.read_text())
            required = fh_data.get("required_headers", [])
            optional = fh_data.get("optional_headers", [])
            if required:
                fuzzing_headers_section = "\n## 【注意】Fuzzing 基础设施头文件（必须 include）\n\n"
                for h in required:
                    hpath = Path(h['path']).name
                    fuzzing_headers_section += f"- `#include \"{hpath}\"` — {h.get('reason','')}\n"
            # include 白名单
            allowed_headers = set()
            for h in required: allowed_headers.add(Path(h['path']).name)
            for h in optional: allowed_headers.add(Path(h['path']).name)
            if allowed_headers:
                fuzzing_headers_section += "\n## 头文件白名单（只允许 include 以下）\n"
                for h in sorted(allowed_headers)[:30]:
                    fuzzing_headers_section += f"- `{h}`\n"
            # helper API 清单（复用旧逻辑的 extract_helper_signatures）
            helper_sigs = extract_helper_signatures(fh_data)
            if helper_sigs:
                fuzzing_headers_section += "\n## 可用 Helper 函数/宏清单\n"
                for hname, sigs in helper_sigs.items():
                    fuzzing_headers_section += f"### {hname} 提供\n```c\n" + "\n".join(sigs[:10]) + "\n```\n"
        except Exception as e:
            print(f"  [warn] fuzzing_headers 加载失败: {e}")

    # ── 5. header_map_section（复用旧逻辑：API→头文件精确映射）──
    header_api_map = build_header_api_map(str(src_dir), api_names)
    header_map_lines = [f"- `{name}` → `#include <{header_api_map.get(name)}>`"
                        for name in api_names if header_api_map.get(name)]
    header_map_section = ("## API→头文件精确映射\n" + "\n".join(header_map_lines[:30]) + "\n") if header_map_lines else ""

    # ── 6. constants_section（复用旧逻辑：枚举/typedef）──
    constants_section = format_constants_section(sig_cache, api_names)

    # ── 7. version_section（复用旧逻辑）──
    version_section = build_version_section(src_dir)

    # ── 8. template_section（复用旧逻辑：init/cleanup 模式）──
    template_section = build_template_section(template_data)

    # ── 9. sequence_section —— 换成 plan 骨架槽位（核心改动）──
    def _param_count(sig: str) -> int:
        """从签名提取参数数量（数顶层逗号）。"""
        if "(" not in sig or ")" not in sig:
            return -1
        inner = sig[sig.index("(") + 1: sig.rindex(")")]
        inner = inner.strip()
        if not inner or inner == "void":
            return 0
        # 粗切顶层逗号（不处理嵌套括号的边界情况，够用）
        depth = 0
        n = 1
        for ch in inner:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                n += 1
        return n

    skel_lines = ["## 骨架调用序列（按此顺序构造 driver，每槽用候选 API 填充）\n"]
    skel_lines.append("**【严格约束】只允许调用下方每个 slot 列出的候选 API，"
                      "不要调用其他任何 API（包括看似相关的变体）。"
                      "每个 API 必须严格按 signature 的参数数量传参——"
                      "too few/many arguments 会导致编译失败。**\n")
    for idx, role in enumerate(skeleton):
        slot = next((s for s in slots if s.get("index") == idx), None)
        fc = slot.get("fill_count", [1, 1]) if slot else [1, 1]
        cands = slot.get("candidates", []) if slot else []
        skel_lines.append(f"{idx+1}. **{role}** (填 {fc[0]}-{fc[1]} 个 API):")
        if cands:
            for c in cands[:3]:
                sig = signatures.get(c["api"], c.get("signature", ""))
                hdr = c.get("header", "") or (header_api_map.get(c["api"]) or "")
                np = _param_count(sig)
                np_tag = f"（必须传 {np} 个参数）" if np >= 0 else ""
                skel_lines.append(f"   - `{c['api']}`{np_tag} — `{sig}` (header: {hdr})")
        else:
            skel_lines.append(f"   - (无候选，从本项目已测 API 中选一个 {role} 角色的补)")
    sequence_section = "\n".join(skel_lines)

    # ── 10. usage_section（基础质量段：本项目完整范例 + 每 API snippets，三模式都有）
    usage_section = ""
    # 本项目完整范例（基础段，三模式都给——帮 LLM 理解本项目 API 调用范式）
    examples = _find_complete_driver_examples(project, lang)
    if examples:
        usage_section = "\n## 【参考代码】本项目已验证 driver（基础参考，必读）\n"
        for ex in examples[:1]:
            usage_section += f"### `{ex['file']}` ({ex['lines']} 行)\n```{ex['lang']}\n{ex['code'][:8000]}\n```\n"

    # 每 API usage snippet（基础段，三模式都给——真实 API 调用片段，非完整模板）
    snippets = find_usage_examples(project, api_names, max_snippets=15)
    if snippets:
        usage_section += "\n## 候选 API 的正确用法（参考，每段只示范单 API 调用）\n"
        shown_apis = set()
        for s in snippets:
            api = s.get("api")
            if api in api_names and api not in shown_apis:
                shown_apis.add(api)
                snippet_lang = "cpp" if s.get("is_cpp") else "c"
                src_tag = s.get("source_tag", "")
                usage_section += f"### `{api}` 用法 (来自 {s.get('file','')}{src_tag}):\n```{snippet_lang}\n{s['code'][:1500]}\n```\n"
            if len(shown_apis) >= 8:
                break

    # ── 11. 差异化侧重段（按模式注入不同引导信息）──
    mode_section = ""
    if mode == "focus":
        # focus 侧重：未测 API 位置提示（plan evidence 已含插入理由 + 未测 API 角色分布）
        evidence_why = plan_driver.get("evidence", {}).get("why", "")
        mode_section = "\n## 【focus 模式侧重】未测 API 插入指引\n"
        if evidence_why:
            mode_section += f"**插入理由**: {evidence_why}\n"
        # 本项目未测 API 按角色分组（从 role_labels 取，scored.json coverage=0 的子集）
        role_dist = load_project_role_distribution(project)
        if role_dist:
            mode_section += "\n**本项目 API 角色分布**（用于在空 slot 按角色选 API）:\n"
            for role in ("create", "configure", "process", "data_sink", "destroy"):
                apis = role_dist.get(role, [])
                if apis:
                    mode_section += f"- {role}: {', '.join(apis[:8])}{' ...' if len(apis)>8 else ''}\n"
    elif mode == "peer":
        # peer 侧重：同场景项目 API 角色分布 + 调用模式摘要（不给同场景完整范例，防语料污染）
        peer_projects = [p.get("name", "") for p in (template_data.get("peer_projects") or [])[:3] if p.get("name")]
        mode_section = "\n## 【peer 模式侧重】同场景项目 API 组织方式参考\n"
        if peer_projects:
            mode_section += f"**同场景标杆项目**: {', '.join(peer_projects)}\n"
        # 本项目 API 角色分布（帮 LLM 理解骨架 slot 的语义角色）
        role_dist = load_project_role_distribution(project)
        if role_dist:
            mode_section += "\n**本项目 API 角色分布**（骨架 slot 角色对应这些 API）:\n"
            for role in ("create", "configure", "process", "data_sink", "destroy"):
                apis = role_dist.get(role, [])
                if apis:
                    mode_section += f"- {role} ({len(apis)} 个): {', '.join(apis[:6])}{' ...' if len(apis)>6 else ''}\n"
        # slot 填充率提示
        empty_slots = [s for s in slots if not s.get("candidates")]
        if empty_slots:
            mode_section += f"\n**注意**: {len(empty_slots)} 个 slot 无候选 API，需按 slot 的 role 自行从上方角色分布选 API\n"
    elif mode == "cross":
        # cross 侧重：骨架来源场景说明 + 跨场景适配指引 + 本项目 API 角色标签
        skel_id = plan_driver.get("skeleton_id", "")
        sk_info = load_skeleton_source_info(skel_id)
        mode_section = "\n## 【cross 模式侧重】跨场景骨架迁移指引\n"
        # 1. 骨架来源场景说明
        mode_section += f"**骨架来源**: `{skel_id}` (distance_to_own={plan_driver.get('distance_to_own','?')})\n"
        if sk_info:
            mode_section += f"- **骨架序列**: {' → '.join(sk_info.get('sequence', []))}\n"
            mode_section += f"- **支持 driver 数**: {sk_info.get('support_drivers', 0)}\n"
            support_projects = sk_info.get("support_projects", [])
            if support_projects:
                mode_section += f"- **来源项目类型**: {', '.join(support_projects[:6])}\n"
            scenarios = sk_info.get("scenarios", {})
            if scenarios:
                top_scenarios = sorted(scenarios.items(), key=lambda x: -x[1])[:3]
                mode_section += f"- **主要场景**: {', '.join(f'{s}({c})' for s,c in top_scenarios)}\n"
            mode_section += f"- **场景置信度**: {sk_info.get('scenario_confidence', '?')}\n"
        # 2. 跨场景适配指引
        mode_section += "\n**跨场景适配指引**:\n"
        mode_section += "- 该骨架源自其他场景项目，slot 角色是抽象的；需把抽象 slot 映射到本项目对应角色的 API\n"
        mode_section += "- 语义对齐: process slot 在压缩库→压缩/解压 API；在图像库→解码 API；在协议库→解析 API\n"
        mode_section += "- data_sink slot: 接收 fuzzer 输入字节的 API（如 write/feed/parse）\n"
        mode_section += "- 空 slot 时按 role 从下方本项目角色分布选 API，不要臆造不存在的 API\n"
        # 3. 本项目 API 角色标签分布
        role_dist = load_project_role_distribution(project)
        if role_dist:
            mode_section += "\n**本项目 API 角色标签分布**（按角色填 slot）:\n"
            for role in ("create", "configure", "process", "data_sink", "destroy"):
                apis = role_dist.get(role, [])
                if apis:
                    mode_section += f"- {role} ({len(apis)} 个): {', '.join(apis[:6])}{' ...' if len(apis)>6 else ''}\n"
        # slot 填充率提示
        empty_slots = [s for s in slots if not s.get("candidates")]
        if empty_slots:
            mode_section += f"\n**注意**: {len(empty_slots)} 个 slot 无候选 API，需按 slot 的 role + 上方角色分布自行选 API\n"

    # 文件名提示（id_suffix 放 mode 前，保持 _crfuzzer 结尾以匹配 step3 glob）
    first_cand = ""
    for s in slots:
        if s.get("candidates"):
            first_cand = s["candidates"][0]["api"].replace("-", "_")
            break
    # driver_id 形如 "focus#1"，取 # 后数字做后缀
    drv_id = plan_driver.get("id", "")
    id_suffix = ""
    if "#" in drv_id:
        id_suffix = drv_id.rsplit("#", 1)[1]
    name_part = first_cand if first_cand else project
    if id_suffix:
        file_hint = f"{name_part}_{id_suffix}_{mode}_crfuzzer.{ext}"
    else:
        file_hint = f"{name_part}_{mode}_crfuzzer.{ext}"

    # 项目背景
    scenario = ""
    peer_projects_list = []
    if scored_data_path.exists():
        sd = json.loads(scored_data_path.read_text())
        scenario = sd.get("scenario", "")
        peer_projects_list = [p.get("name", "") for p in (sd.get("peer_projects") or [])[:3] if p.get("name")]

    peer_projects_str = ", ".join(peer_projects_list) if peer_projects_list else "无"

    prompt = f"""{lang_guide}

## 项目背景
- **库**: {project}
- **场景**: {scenario}
- **模式**: {mode}
- **骨架来源**: {plan_driver.get('skeleton_id', '?')} (distance_to_own={plan_driver.get('distance_to_own', '?')})
- {plan_driver.get('evidence', {}).get('why', '')}
- **同场景标杆项目**: {peer_projects_str}

{build_info}

## 主要头文件
{header_info}

{fuzzing_headers_section}
{header_map_section}
{constants_section}
{version_section}

{template_section}

{sequence_section}

{usage_section}
{mode_section}
## 生成要求

请生成完整的 libFuzzer fuzz driver 源文件，文件名 `{file_hint}`：

1. **按骨架顺序**: 严格按上方骨架序列顺序构造调用。每槽用候选 API 填充（参数从 signature 读取，不要猜）。
2. **资源生命周期**: create 槽分配 → configure/data_sink/process 使用 → destroy 槽释放。所有 return 路径都要释放资源。
3. **Fuzzer 输入**: data_sink 槽的 API 接收 `data`/`size`；其余槽如需输入，从 `data` 切分。
4. **错误处理**: 返回指针的函数检查 NULL，返回错误码的检查非零；错误路径释放资源后 `return 0`。
5. **头文件**: 只 `#include` 实际需要的（标准库 + 目标库头文件，从候选 API 的 header 字段取）。
6. **不透明结构体**: 用工厂函数分配，不要栈分配未知大小的结构体。

请**只输出完整源代码**（在 ```{code_block} 代码块中），不要其他说明。
"""
    return prompt, lang, file_hint


def generate_one_driver_from_plan(args):
    """plan 驱动的单 driver 生成（替代旧 generate_one_driver）。

    args = (project, mode, plan_driver, template_data, src_dir_str,
            driver_idx, api_key, base_url, fast_model, strong_model, provider)
    返回 (code, plan_driver_id, driver_idx, mode, lang, file_hint)
    """
    (project, mode, plan_driver, template_data, src_dir_str,
     driver_idx, api_key, base_url, fast_model, strong_model, provider) = args

    try:
        prompt, lang, file_hint = build_prompt_from_plan(
            project, mode, plan_driver, template_data, src_dir_str)
    except Exception as e:
        print(f"  [{mode}#{driver_idx}] prompt 构建失败: {e}")
        return (None, plan_driver.get("id"), driver_idx, mode, "c", "")

    drv_id = plan_driver.get("id", f"{mode}#{driver_idx}")
    print(f"  [{drv_id}] {mode} 生成中...")

    code = None
    # Stage 1: 快模型 3 次
    for attempt in range(3):
        response = call_llm(prompt, fast_model, api_key, base_url, provider)
        if not response:
            continue
        code = extract_code(response)
        if is_valid_driver(code):
            print(f"  [{drv_id}] ✅ 快模型成功 ({len(code.splitlines())} 行)")
            break
        code = None

    # Stage 2: 强模型兜底 3 次
    if code is None:
        for attempt in range(3):
            response = call_llm(prompt, strong_model, api_key, base_url, provider)
            if not response:
                continue
            code = extract_code(response)
            if is_valid_driver(code):
                print(f"  [{drv_id}] ✅ 强模型成功 ({len(code.splitlines())} 行)")
                break
            code = None

    if code is None:
        print(f"  [{drv_id}] ❌ 均失败")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    # ── 校验器（Phase 8: 恢复 L2/L3 拦截）──
    # L1: include 白名单（仍拦截）
    inc_ok, inc_violations = validate_driver_includes(code, project)
    if not inc_ok:
        print(f"  [{drv_id}] ❌ L1 include 违规: {inc_violations[:3]}")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    # L4: 平台头（仍拦截）
    plat_ok, plat_violations = validate_platform_headers(code)
    if not plat_ok:
        print(f"  [{drv_id}] ❌ L4 平台头冲突: {plat_violations[:3]}")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    # L2: 臆造调用（降级警告：白名单不全会导致标准库函数误拦，让 build 阶段兜底）
    sig_cache = build_signature_cache(src_dir_str)
    fh_data = _load_fh_data(project)
    call_ok, fake_calls, blk_hits = validate_driver_calls(code, project, sig_cache, fh_data)
    if not call_ok:
        print(f"  [{drv_id}] ⚠️ [L2 警告] 疑似臆造调用: {sorted(fake_calls)[:5]}，照常保存（build 阶段兜底）")

    # L3: 类型可见性（Phase 8: 恢复拦截）
    type_ok, invisible_types = validate_driver_types(code, project, sig_cache)
    if not type_ok:
        print(f"  [{drv_id}] ❌ L3 不可见类型: {sorted(invisible_types)[:5]}")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    return (code, drv_id, driver_idx, mode, lang, file_hint)


# ─── Main ───────────────────────────────────────────────────────────

def _run_peer_cross_mode(project, mode, template_data, src_dir,
                         target_count, api_key, base_url, fast_model, strong_model):
    """plan 驱动模式（focus/peer/cross 通用）。

    加载 plan_<mode>.json → build_prompt_from_plan → LLM 生成 → L1/L4 硬拦 + L2 警告 + L3 硬拦。
    产出 driver 到 output/<project>/driver/<mode>/*_<mode>_crfuzzer.{ext}。
    """
    try:
        plan = load_plan(project, mode)
    except Exception as e:
        print(f"  [{mode}] plan 加载失败: {e}")
        return []

    plan_drivers = plan.get("drivers", [])[:target_count]
    if not plan_drivers:
        print(f"  [{mode}] plan 无 driver")
        return []

    worker_args = [
        (project, mode, pd, template_data, str(src_dir),
         i, api_key, base_url, fast_model, strong_model, LLM_PROVIDER)
        for i, pd in enumerate(plan_drivers)
    ]

    max_workers = max(1, min(target_count, int(os.getenv("STEP2_MAX_WORKERS", "8"))))
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(generate_one_driver_from_plan, args): args[4]
                   for args in worker_args}
        for future in as_completed(futures):
            try:
                code, drv_id, idx, m, lang, file_hint = future.result()
                results.append((code, drv_id, idx, m, lang, file_hint))
            except Exception as e:
                print(f"  [{mode}] worker 异常: {e}")

    mode_out = output_for(project, mode)
    mode_out.mkdir(parents=True, exist_ok=True)
    generated = []
    for code, drv_id, idx, m, lang, file_hint in results:
        if code is None:
            continue
        ext = file_hint.split(".")[-1] if file_hint else ("cpp" if lang == "cpp" else "c")
        name = file_hint.rsplit(".", 1)[0] if file_hint else f"{project}_{mode}_{idx}_crfuzzer"
        if f"_{mode}_crfuzzer" not in name:
            name = f"{name}_{mode}_crfuzzer"
        out_file = mode_out / f"{name}.{ext}"
        out_file.write_text(code)
        generated.append({"mode": mode, "name": name, "file": str(out_file),
                          "driver_id": drv_id})
        print(f"  [{drv_id}] ✅ {name} → {out_file}")
    return generated


def main():
    if len(sys.argv) < 2:
        print("Usage: python step2_generate.py <project> [num_drivers=5] [--mode=focus|peer|cross|all]")
        sys.exit(1)

    project = sys.argv[1]
    target_count = 5
    modes = list(MODES)
    for a in sys.argv[2:]:
        if a.startswith("--mode="):
            m = a.split("=", 1)[1]
            if m == "all":
                modes = list(MODES)
            elif m in MODES:
                modes = [m]
            else:
                print(f"[Step2] --mode 非法: {m}")
                sys.exit(1)
        elif a.isdigit():
            target_count = int(a)

    proj_dir = intermediate_for(project)
    scored_file = proj_dir / "scored.json"
    if not scored_file.exists():
        print(f"[Step2] 错误: {scored_file} 不存在，请先运行 step1_prepare.py")
        sys.exit(1)

    scored_data = json.loads(scored_file.read_text())
    template_data = load_template(project) or {}
    src_dir = SRC_DIR / project
    if not src_dir.exists():
        print(f"[Step2] 错误: 源码目录 {src_dir} 不存在")
        sys.exit(1)

    _api_key = DEEPSEEK_API_KEY
    _base_url = DEEPSEEK_BASE_URL
    _fast_model = DEEPSEEK_FAST_MODEL
    _strong_model = DEEPSEEK_MODEL

    print(f"\n[Step2] 骨架驱动生成 | 项目={project} | 模式={modes} | "
          f"每模式上限={target_count}")
    print(f"  三模式统一走 plan 驱动（build_prompt_from_plan + L2/L3 拦截）")

    sig_cache = build_signature_cache(str(src_dir))
    print(f"  签名缓存: {len(_sig_names(sig_cache))} 个")

    all_generated = []
    for mode in modes:
        print(f"\n[Step2] [{mode}] 生成中...")
        generated = _run_peer_cross_mode(project, mode, template_data,
                                         src_dir, target_count,
                                         _api_key, _base_url,
                                         _fast_model, _strong_model)
        all_generated.extend(generated)

    # ── manifest ──
    manifest = {
        "project": project,
        "modes": modes,
        "num_generated": len(all_generated),
        "fast_model": _fast_model,
        "strong_model": _strong_model,
        "drivers": [{"mode": g["mode"], "name": g["name"], "file": g["file"]}
                    for g in all_generated],
    }
    manifest_file = proj_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

    print(f"\n[Step2] {'='*40}")
    print(f"  生成: {len(all_generated)} 个 driver | 模式: {modes}")
    for g in all_generated:
        print(f"    [{g['mode']}] ✅ {g['name']}")


if __name__ == "__main__":
    main()