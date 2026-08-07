#!/usr/bin/env python3
"""Step1 Section B：驱动模板提取 → template.json。"""
# 从 step1_prepare.py 阶段2 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import re
from pathlib import Path
from collections import Counter
from config import PROJECTS_DIR, intermediate_for

# ══════════════════════════════════════════════════════════════════════
# Section B: 驱动模板提取
# ══════════════════════════════════════════════════════════════════════

def find_project_drivers(project):
    proj_dir = PROJECTS_DIR / project
    if not proj_dir.exists():
        return []
    drivers = []
    for pat in ["*.c", "*.cc", "*.cpp"]:
        for f in proj_dir.glob(pat):
            if "standalone" in f.name.lower():
                continue
            drivers.append(f)
    return sorted(drivers)


def parse_driver_structure(filepath):
    try:
        text = filepath.read_text(errors="ignore")
    except Exception:
        return None

    result = {
        "file": str(filepath), "filename": filepath.name,
        "includes": [], "init_calls": [], "business_calls": [],
        "cleanup_calls": [], "data_strategy": "unknown",
        "pattern_type": "unknown", "has_stateful_context": False,
        "max_input_size": None,
    }

    result["includes"] = re.findall(r'^\s*#include\s+[<"](.+?)[>"]', text, re.MULTILINE)

    m = re.search(r'LLVMFuzzerTestOneInput\s*\([^)]*\)\s*\{(.*?)\n\}', text, re.DOTALL)
    func_body = m.group(1) if m else ""

    c_keywords = {
        'if', 'for', 'while', 'switch', 'return', 'sizeof', 'assert',
        'malloc', 'free', 'calloc', 'realloc', 'memcpy', 'memset',
        'memcmp', 'strlen', 'strcmp', 'strncmp', 'strcpy', 'strdup',
        'printf', 'fprintf', 'fread', 'fopen', 'fclose', 'exit',
        'FUZZ_ASSERT', 'FUZZ_ZASSERT', 'FUZZ_ASSERT_MSG',
    }
    all_calls = re.findall(r'\b(\w+)\s*\(', func_body)
    api_calls = [c for c in all_calls if c not in c_keywords]

    init_kw = {'init', 'create', 'new', 'open', 'setup', 'start', 'begin'}
    cleanup_kw = {'destroy', 'free', 'close', 'cleanup', 'release', 'unref',
                  'delete', 'shutdown', 'finish', 'end'}
    cleanup_exclude = {'append', 'decompress', 'compress', 'encode', 'decode',
                       'write', 'read', 'get', 'set', 'copy', 'find'}

    for c in api_calls:
        cl = c.lower()
        if any(kw in cl for kw in init_kw):
            result["init_calls"].append(c)
        elif any(kw in cl for kw in cleanup_kw) and not any(ex in cl for ex in cleanup_exclude):
            result["cleanup_calls"].append(c)
        else:
            result["business_calls"].append(c)

    for key in ["init_calls", "business_calls", "cleanup_calls"]:
        result[key] = list(dict.fromkeys(result[key]))

    result["data_strategy"] = _classify_data_strategy(func_body)
    result["pattern_type"] = _classify_pattern(text)
    result["has_stateful_context"] = bool(re.search(
        r'^\s*static\s+\w+\s*\*?\s*\w+\s*=\s*NULL\s*;', text, re.MULTILINE))
    m2 = re.search(r'(?:kMaxSize|MAX_SIZE|max_size)\s*=\s*(\d+)', text)
    if m2:
        result["max_input_size"] = int(m2.group(1))
    return result


def _classify_data_strategy(func_body):
    if not func_body:
        return "unknown"
    if re.search(r'(TLV|tlv|fuzz_get_first_tlv|fuzz_get_next_tlv)', func_body):
        return "tlv"
    if re.search(r'(FUZZ_dataProducer|data_producer)', func_body):
        return "producer"
    if re.search(r'data\s*\[', func_body):
        return "byte-sliced"
    return "direct"


def _classify_pattern(text):
    if re.search(r'(compress|decompress|encode|decode).*(compress|decompress|encode|decode)', text):
        return "round_trip"
    if re.search(r'\b(for|while)\s*\(', text):
        return "multi_api"
    return "parse_only"


# 注：_extract_skeleton 返回布尔特征集（has_size_guard / has_loop 等），不是调用序列骨架，
# 与 tools/step0_tools/skeleton_mine 的角色序列骨架完全是两回事，勿混淆（未改名以避免牵连调用点）。
def _extract_skeleton(driver_text):
    return {
        "has_size_guard": bool(re.search(r'if\s*\(\s*size\s*[<>]', driver_text)),
        "has_null_termination": "strndup" in driver_text,
        "has_loop": bool(re.search(r'\b(for|while)\s*\(', driver_text)),
        "uses_assert": bool(re.search(r'\b(assert|FUZZ_ASSERT)\s*\(', driver_text)),
    }


def _extract_template_from_peers(project, setup_data):
    peer_projects = setup_data.get("peer_projects", [])
    for pp in peer_projects:
        pp_drivers = find_project_drivers(pp["name"])
        if pp_drivers:
            results = []
            for d in pp_drivers[:3]:
                parsed = parse_driver_structure(d)
                if parsed:
                    parsed["source_peer"] = pp["name"]
                    results.append(parsed)
            if results:
                return results
    return []


def _merge_driver_analyses(analyses):
    if not analyses:
        return {}

    merged = {
        "all_includes": [], "common_includes": [], "init_patterns": [],
        "cleanup_patterns": [], "business_patterns": [],
        "pattern_types": [], "data_strategies": [], "max_input_sizes": [],
        "skeletons": [], "num_drivers_analyzed": len(analyses),
    }

    for a in analyses:
        if not a:
            continue
        merged["all_includes"].extend(a["includes"])
        merged["init_patterns"].extend(a["init_calls"])
        merged["business_patterns"].extend(a["business_calls"])
        merged["cleanup_patterns"].extend(a["cleanup_calls"])
        merged["pattern_types"].append(a.get("pattern_type", "unknown"))
        merged["data_strategies"].append(a.get("data_strategy", "unknown"))
        if a.get("max_input_size"):
            merged["max_input_sizes"].append(a["max_input_size"])
        try:
            merged["skeletons"].append(_extract_skeleton(
                Path(a["file"]).read_text(errors="ignore")))
        except Exception:
            pass

    inc_counts = Counter(merged["all_includes"])
    merged["common_includes"] = [inc for inc, cnt in inc_counts.most_common(20) if cnt > 1]

    # 识别 fuzzer 基础设施头文件：被 >=50% driver 引用的本地头文件（非标准库、非项目公开 API）
    _STD_HEADERS = {
        'cstdint', 'cstdlib', 'cstring', 'cstdio', 'cstddef', 'climits',
        'cassert', 'cmath', 'ctime', 'cerrno',
        'stdint.h', 'stdlib.h', 'string.h', 'stdio.h', 'stddef.h', 'limits.h',
        'assert.h', 'math.h', 'time.h', 'errno.h', 'unistd.h', 'fcntl.h',
        'sys/types.h', 'sys/stat.h', 'inttypes.h', 'signal.h', 'setjmp.h',
        'vector', 'string', 'memory', 'algorithm', 'functional', 'limits',
        'array', 'map', 'set', 'deque', 'list', 'queue', 'stack',
        'iostream', 'fstream', 'sstream',
        'fuzzer/FuzzedDataProvider.h',
    }
    _INFRA_KEYWORDS = {'common', 'fuzzer', 'fuzz', 'harness', 'driver'}
    num_analyzed = len(analyses)
    if num_analyzed > 0:
        per_driver_incs = [set(a.get("includes", [])) for a in analyses if a]
        infra_headers = []
        for inc, cnt in inc_counts.items():
            if inc in _STD_HEADERS:
                continue
            # 只关注本地头文件风格（不含路径分隔符超过1层的项目API头文件如 FLAC/stream_decoder.h）
            basename = inc.split('/')[-1].lower().replace('.', '')
            is_infra = any(kw in basename for kw in _INFRA_KEYWORDS)
            # >=50% driver 引用，或名字包含 fuzzer/common 等关键词且被多个 driver 引用
            threshold = num_analyzed * 0.5
            if cnt >= threshold and is_infra:
                infra_headers.append(inc)
            elif cnt >= num_analyzed * 0.8 and '/' not in inc:
                # 80%+ 引用的任何本地头文件也视为必需
                infra_headers.append(inc)
        merged["required_fuzzer_infra_headers"] = infra_headers
    else:
        merged["required_fuzzer_infra_headers"] = []

    for key in ["init_patterns", "cleanup_patterns", "business_patterns"]:
        merged[key] = list(dict.fromkeys(merged[key]))

    strat_counts = Counter(merged["data_strategies"])
    merged["dominant_strategy"] = strat_counts.most_common(1)[0][0] if strat_counts else "direct"
    pat_counts = Counter(merged["pattern_types"])
    merged["dominant_pattern"] = pat_counts.most_common(1)[0][0] if pat_counts else "unknown"

    sizes = merged["max_input_sizes"]
    if sizes:
        sizes.sort()
        merged["median_input_size"] = sizes[len(sizes) // 2]

    ext_counts = Counter()
    for a in analyses:
        if a and 'filename' in a:
            ext_counts[Path(a['filename']).suffix] += 1
    merged['dominant_lang'] = 'cpp' if ext_counts.get('.cpp', 0) + ext_counts.get('.cc', 0) > ext_counts.get('.c', 0) else 'c'
    merged['lang_stats'] = {k: v for k, v in ext_counts.most_common()}

    return merged


def run_template_extraction(project, setup_data):
    """Step B: 驱动模板提取 → template.json"""
    print("\n--- 模板提取 ---")
    project_drivers = find_project_drivers(project)
    print(f"  在 {PROJECTS_DIR}/{project}/ 中找到 {len(project_drivers)} 个 driver")

    all_analyses = []
    if project_drivers:
        for dpath in project_drivers:
            analysis = parse_driver_structure(dpath)
            if analysis:
                analysis["source"] = "own_project"
                all_analyses.append(analysis)
                print(f"    {dpath.name}: init={len(analysis['init_calls'])}, "
                      f"biz={len(analysis['business_calls'])}, "
                      f"cleanup={len(analysis['cleanup_calls'])}, "
                      f"strategy={analysis['data_strategy']}, pattern={analysis['pattern_type']}")

    if not all_analyses:
        print(f"  项目 {project} 无专属 driver，尝试同类项目...")
        peer_analyses = _extract_template_from_peers(project, setup_data)
        if peer_analyses:
            all_analyses = peer_analyses
            print(f"  从同类项目获取了 {len(all_analyses)} 个 driver 模板")

    template = _merge_driver_analyses(all_analyses)
    template["project"] = project
    template["source_type"] = "own_project" if project_drivers else (
        "peer_project" if all_analyses else "generic")

    proj_dir = intermediate_for(project)
    out_file = proj_dir / "template.json"
    with open(out_file, "w") as f:
        json.dump(template, f, indent=2, ensure_ascii=False)

    print(f"  分析 driver: {template['num_drivers_analyzed']} 个")
    print(f"  主要策略: {template.get('dominant_strategy', 'N/A')}")
    print(f"  主要模式: {template.get('dominant_pattern', 'N/A')}")
    print(f"  → {out_file}")
    return template
