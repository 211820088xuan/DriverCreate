#!/usr/bin/env python3
"""Step2 上下文构建：用法范例 / 版本 / 模板段落（喂给 prompt）。"""
# 从 step2_generate.py 阶段3 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import os
import re
from config import INTERMEDIATE_DIR, PROJECTS_DIR, SRC_DIR
from tools.step2_tools.validators import _STDLIB_C

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
