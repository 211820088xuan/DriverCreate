#!/usr/bin/env python3
"""Step2 签名缓存：扫头文件建函数/结构体/常量缓存 + API→头文件映射。"""
# 从 step2_generate.py 阶段3 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import os
import re
from config import INTERMEDIATE_DIR

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

def _sig_names(sig_cache):
    """兼容新旧 sig_cache 格式: 扁平 dict 或嵌套 {'functions': {...}} """
    if isinstance(sig_cache, dict) and "functions" in sig_cache:
        return sig_cache["functions"]
    return sig_cache
