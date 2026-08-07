#!/usr/bin/env python3
"""
Step 1: 项目情报收集 — 图谱情报 + 驱动模板 + 构建参数 + API 打分

输入: project_name
输出: intermediate/<project>/ 下的 setup.json, template.json,
      build_profile.json, scored.json

四个阶段:
  A 图谱情报查询  (Neo4j)  → setup.json
  B 驱动模板提取           → template.json
  C 构建 Profile 提取      → build_profile.json
  D API 分类 & 打分        → scored.json
"""

import sys
import json
import os
import re
from pathlib import Path
from collections import Counter

from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE,
    INTERMEDIATE_DIR, SRC_DIR, OSS_FUZZ_DIR, PROJECTS_DIR,
    VENDOR_SKIP_DIRS,
    intermediate_for,
)
# 源码自动克隆（与 step3_build 同源，幂等：目录已存在则直接返回 True）
from agent import agent_main

# ─── Neo4j 可选 ────────────────────────────────────────────────────
try:
    from neo4j import GraphDatabase, basic_auth
    HAS_NEO4J = True
except ImportError:
    HAS_NEO4J = False



# ══════════════════════════════════════════════════════════════════════
# Section A: 图谱情报查询
# ══════════════════════════════════════════════════════════════════════

def query_project_graph(project):
    """从 Neo4j 图谱中查询项目相关信息"""
    if not HAS_NEO4J:
        print("  [图谱] neo4j 未安装，跳过")
        return None

    if not NEO4J_PASSWORD:
        print("  [图谱] NEO4J_PASSWORD 环境变量未设置，跳过图谱查询")
        return None

    driver = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))
    info = {
        "project": project,
        "scenarios": [],
        "own_drivers": [],
        "own_crashes": [],
        "own_drivers_detail": [],
        "crash_driver_links": [],
        "peer_projects": [],
        "crash_apis": [],
        "all_apis": [],
        "untested_apis": [],
        "tested_apis": [],
        "peer_driver_patterns": [],
        "api_dependencies": {},
    }

    with driver.session(database=NEO4J_DATABASE) as session:
        # Q1: Scenario
        result = session.run("""
            MATCH (lib:Library {name: $proj})-[:APPLY_TO]->(s:Scenario)
            RETURN s.name AS name, s.description AS desc
        """, proj=project)
        info["scenarios"] = [{"name": r["name"], "description": r["desc"]} for r in result]

        # Q2: Driver & Crash
        result = session.run("""
            MATCH (lib:Library {name: $proj})
            OPTIONAL MATCH (lib)-[:HAS_DRIVER]->(d)
            WITH lib, collect(DISTINCT d.name) AS drivers
            OPTIONAL MATCH (lib)-[:HAS_CRASH]->(c)
            RETURN drivers, collect(DISTINCT c.name)[..30] AS crashes
        """, proj=project)
        for r in result:
            info["own_drivers"] = r["drivers"] or []
            info["own_crashes"] = r["crashes"] or []

        # Q3: Driver → CALLS → API
        result = session.run("""
            MATCH (lib:Library {name: $proj})-[:HAS_DRIVER]->(d)
            OPTIONAL MATCH (d)-[:CALLS]->(a)
            WHERE a:CAPI OR a:API
            RETURN d.name AS driver, collect(DISTINCT a.name) AS apis
        """, proj=project)
        for r in result:
            info["own_drivers_detail"].append({
                "driver": r["driver"], "apis": r["apis"] or []
            })

        # Q4: Crash → Driver 关联
        result = session.run("""
            MATCH (lib:Library {name: $proj})-[:HAS_DRIVER]->(d)-[:TRIGGER]->(c)
            RETURN d.name AS driver, c.name AS crash, c.crash_type AS crash_type,
                   c.sanitizer AS sanitizer, c.security_severity AS severity
            ORDER BY driver, crash
            LIMIT 30
        """, proj=project)
        for r in result:
            info["crash_driver_links"].append({
                "driver": r["driver"], "crash": r["crash"],
                "crash_type": r["crash_type"], "sanitizer": r["sanitizer"],
                "severity": r["severity"],
            })

        # Q5: 同类标杆项目
        if info["scenarios"]:
            scenario_name = info["scenarios"][0]["name"]
            result = session.run("""
                MATCH (s:Scenario {name: $scenario})<-[:APPLY_TO]-(peer:Library)
                WHERE peer.name <> $proj
                OPTIONAL MATCH (peer)-[:HAS_CRASH]->(c)
                OPTIONAL MATCH (peer)-[:HAS_DRIVER]->(d)
                WITH peer, count(DISTINCT c) AS crash_count, count(DISTINCT d) AS driver_count
                WHERE crash_count > 0
                RETURN peer.name AS name, crash_count, driver_count
                ORDER BY crash_count DESC LIMIT 5
            """, scenario=scenario_name, proj=project)
            info["peer_projects"] = [dict(r) for r in result]

        # Q6: 所有 API（含 api_enrich 富化字段：签名/参数/返回类型/头文件/描述）
        result = session.run("""
            MATCH (lib:Library {name: $proj})-[:HAS_API]->(a)
            WHERE a:CAPI OR a:API
            RETURN a.name AS name, a.lang AS lang,
                   a.signature AS signature, a.return_type AS return_type,
                   a.params AS params, a.param_count AS param_count,
                   a.header AS header, a.header_path AS header_path,
                   a.description AS description, a.desc_source AS desc_source
            ORDER BY name
            LIMIT 2000
        """, proj=project)
        info["all_apis"] = [{
            "name": r["name"], "lang": r["lang"],
            "signature": r["signature"] or "",
            "return_type": r["return_type"] or "",
            "params": r["params"] or [],
            "param_count": r["param_count"] or 0,
            "header": r["header"] or "",
            "header_path": r["header_path"] or "",
            "description": r["description"] or "",
            "desc_source": r["desc_source"] or "",
        } for r in result]

        # Q7: 未测 API（本项目 driver 没调过，而非全图无人调用——focus 规则2 要这批）
        result = session.run("""
            MATCH (lib:Library {name: $proj})-[:HAS_API]->(a)
            WHERE a:CAPI OR a:API
            OPTIONAL MATCH (lib)-[:HAS_DRIVER]->(d)-[:CALLS]->(a)
            WITH a, count(DISTINCT d) AS driver_count
            WHERE driver_count = 0
            RETURN a.name AS name
            ORDER BY name
            LIMIT 500
        """, proj=project)
        info["untested_apis"] = [r["name"] for r in result]

        # Q7b: 已测 API
        result = session.run("""
            MATCH (lib:Library {name: $proj})-[:HAS_API]->(a)
            WHERE a:CAPI OR a:API
            MATCH (d)-[:CALLS]->(a)
            WITH a, collect(DISTINCT d.name) AS drivers
            RETURN a.name AS name, drivers
            ORDER BY name
            LIMIT 500
        """, proj=project)
        info["tested_apis"] = [{"name": r["name"], "drivers": r["drivers"]} for r in result]

        # Q8: 同类项目 driver-API 模式
        if info["scenarios"]:
            scenario_name = info["scenarios"][0]["name"]
            result = session.run("""
                MATCH (s:Scenario {name: $scenario})<-[:APPLY_TO]-(peer:Library)
                WHERE peer.name <> $proj
                MATCH (peer)-[:HAS_DRIVER]->(d)-[:CALLS]->(a)
                WHERE a:CAPI OR a:API
                RETURN peer.name AS peer, d.name AS driver, collect(DISTINCT a.name) AS apis
                ORDER BY peer, driver
                LIMIT 50
            """, scenario=scenario_name, proj=project)
            info["peer_driver_patterns"] = [{
                "peer": r["peer"], "driver": r["driver"], "apis": r["apis"]
            } for r in result]

            # Q9: API 共现关系 + 顺序一致率（v3 改：加 order_last 顺序证据）
            # §7.1 focus 规则 2 依赖「共现 ≥3 + 顺序一致率 ≥90%」
            untested_names = info["untested_apis"][:30]
            api_deps = {}
            for api_name in untested_names:
                result = session.run("""
                    MATCH (lib:Library {name: $proj})-[:HAS_DRIVER]->(d)-[c1:CALLS]->(a1)
                    WHERE a1.name = $api_name AND c1.order_last IS NOT NULL
                    MATCH (lib)-[:HAS_DRIVER]->(d)-[c2:CALLS]->(a2)
                    WHERE a2.name <> $api_name AND (a2:CAPI OR a2:API)
                       AND c2.order_last IS NOT NULL
                    WITH a2, count(DISTINCT d) AS cooccur,
                         sum(CASE WHEN c1.order_last < c2.order_last THEN 1 ELSE 0 END) AS ordered_before
                    RETURN a2.name AS co_api, cooccur AS freq,
                           CASE WHEN cooccur > 0
                                THEN toFloat(ordered_before) / cooccur
                                ELSE 0.0 END AS order_consistency
                    ORDER BY freq DESC LIMIT 10
                """, proj=project, api_name=api_name)
                deps = [{"api": r["co_api"], "freq": r["freq"],
                         "order_consistency": round(r["order_consistency"], 3)}
                        for r in result]
                if deps:
                    api_deps[api_name] = deps
            info["api_dependencies"] = api_deps

    driver.close()
    return info


def run_graph_setup(project):
    """Step A: 图谱情报查询 → setup.json"""
    print("\n--- 图谱情报 ---")
    info = query_project_graph(project)
    if info is None:
        print("  图谱不可用，创建空信息")
        info = {
            "project": project, "scenarios": [], "own_drivers": [],
            "own_crashes": [], "peer_projects": [], "crash_driver_links": [],
            "all_apis": [], "untested_apis": [], "tested_apis": [],
            "peer_driver_patterns": [], "api_dependencies": {},
        }

    ossfuzz_proj_dir = OSS_FUZZ_DIR / "projects" / project
    info["ossfuzz_exists"] = ossfuzz_proj_dir.exists()
    info["ossfuzz_dir"] = str(ossfuzz_proj_dir)

    src_dir = SRC_DIR / project
    info["src_exists"] = src_dir.exists()
    info["src_dir"] = str(src_dir)

    proj_dir = intermediate_for(project)
    out_file = proj_dir / "setup.json"
    with open(out_file, "w") as f:
        json.dump(info, f, indent=2, ensure_ascii=False)

    print(f"  Scenario: {[s['name'] for s in info['scenarios']]}")
    print(f"  自身 Driver: {len(info.get('own_drivers', []))} 个")
    print(f"  自身 Crash: {len(info.get('own_crashes', []))} 个")
    print(f"  自身 API: {len(info.get('all_apis', []))} 个")
    print(f"  未测 API: {len(info.get('untested_apis', []))} 个")
    print(f"  已测 API: {len(info.get('tested_apis', []))} 个")
    print(f"  共现关系: {len(info.get('api_dependencies', {}))} 个 API")
    peers = info.get("peer_projects", [])
    if peers:
        peer_str = ', '.join(f"{p['name']}(crash={p['crash_count']})" for p in peers)
        print(f"  标杆项目: {peer_str}")
    print(f"  → {out_file}")
    return info


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


# ══════════════════════════════════════════════════════════════════════
# Section C: 构建 Profile 提取
# ══════════════════════════════════════════════════════════════════════

def _detect_build_system(src_dir):
    result = {"type": "unknown", "files": []}
    cmake = src_dir / "CMakeLists.txt"
    if cmake.exists():
        result["type"] = "cmake"
        result["files"].append(str(cmake))
        for sub in ["tests/fuzz", "fuzz", "test/fuzz"]:
            p = src_dir / sub / "CMakeLists.txt"
            if p.exists():
                result["files"].append(str(p))

    configure = src_dir / "configure"
    configure_ac = src_dir / "configure.ac"
    makefile_am = src_dir / "Makefile.am"
    if configure.exists() or (configure_ac.exists() and makefile_am.exists()):
        result["type"] = "autotools"
        if configure_ac.exists():
            result["files"].append(str(configure_ac))
        if makefile_am.exists():
            result["files"].append(str(makefile_am))
        for sub in ["fuzz", "tests/fuzz"]:
            p = src_dir / sub / "Makefile.am"
            if p.exists():
                result["files"].append(str(p))

    meson = src_dir / "meson.build"
    if meson.exists():
        result["type"] = "meson"
        result["files"].append(str(meson))

    makefiles = list(src_dir.glob("Makefile*"))
    if makefiles and result["type"] == "unknown":
        result["type"] = "makefile"
        result["files"].extend(str(m) for m in makefiles[:3])
    return result


def _extract_from_cmake(src_dir, profile):
    cmake_file = src_dir / "CMakeLists.txt"
    content = cmake_file.read_text()

    if "FetchContent" in content:
        profile["has_fetchcontent"] = True
        deps = re.findall(r'FetchContent_Declare\s*\(\s*(\w+)', content)
        known_deps = {
            "zlib": "ZLIB", "zlib_ng": "ZLIB", "zstd": "ZSTD", "lz4": "LZ4",
            "snappy": "SNAPPY", "bzip2": "BZIP2", "xz": "XZ",
            "gtest": "GTEST", "benchmark": "BENCHMARK", "catch2": "CATCH2",
        }
        for dep in deps:
            normalized = known_deps.get(dep.lower())
            if normalized:
                profile.setdefault("cmake_flags", "")
                for flag in [f"-DDEACTIVATE_{normalized}=ON", f"-DPREFER_EXTERNAL_{normalized}=ON"]:
                    if flag not in profile["cmake_flags"]:
                        profile["cmake_flags"] += f" {flag}"

    for m in re.findall(r'option\((\w+)\s+"([^"]*)"', content):
        name, desc = m
        if 'fuzz' in name.lower() or 'fuzz' in desc.lower():
            profile.setdefault("cmake_fuzz_options", {})[name] = desc

    pkgs = re.findall(r'(?:find_package|pkg_check_modules)\s*\((\w+)', content)
    if pkgs:
        profile.setdefault("cmake_dependencies", []).extend(pkgs)

    default_flags = ("-DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF "
                     "-DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF "
                     "-DBUILD_EXAMPLES=OFF -DBUILD_FUZZERS=OFF -DBUILD_PLUGINS=OFF")
    existing = profile.get("cmake_flags", "")
    profile["cmake_flags"] = (default_flags + " " + existing).strip()


def _extract_from_autotools(src_dir, profile):
    fuzz_makefile = None
    for p in [src_dir / "fuzz" / "Makefile.am", src_dir / "tests" / "fuzz" / "Makefile.am"]:
        if p.exists():
            fuzz_makefile = p
            break

    if fuzz_makefile:
        content = fuzz_makefile.read_text()
        for var_name, key in [('AM_CPPFLAGS', 'auto_cppflags'), ('AM_CFLAGS', 'auto_cflags'),
                               ('AM_CXXFLAGS', 'auto_cxxflags'), ('LDADD', 'auto_ldadd')]:
            m = re.findall(rf'{var_name}\s*=\s*(.+?)(?:\n|$)', content)
            if m:
                profile[key] = m[0].strip()

        if "configure_flags" not in profile:
            profile["configure_flags"] = "--enable-static --disable-shared"

    configure_ac = src_dir / "configure.ac"
    if configure_ac.exists():
        for m in re.findall(r'AC_ARG_ENABLE\(\[(\w+)\]', configure_ac.read_text()):
            if 'fuzz' in m.lower() or 'static' in m.lower() or 'shared' in m.lower():
                profile.setdefault("configure_flags_raw", []).append(m)


def _scan_include_dirs(src_dir, template_data):
    dirs = []
    includes = template_data.get("common_includes", []) or template_data.get("all_includes", [])

    for inc in includes:
        header = inc.strip('<>"')
        for root, subdirs, files in os.walk(str(src_dir)):
            depth = root.replace(str(src_dir), "").count(os.sep)
            if depth > 5:
                subdirs.clear()
                continue
            if header in files:
                rel = os.path.relpath(root, src_dir)
                d = "$SRC" if rel == "." else f"$SRC/{rel}"
                if d not in dirs:
                    dirs.append(d)

    # 兜底候选目录：常规头目录 + 库内部头目录（library/core/crypto/common 等）。
    # mbedtls 这类把 common.h 放在 library/ 的项目，官方走 CMake 全量构建会自动带上，
    # 但单文件注入编译需显式补 -I，否则 'common.h' file not found。
    for c in ["include", "includes", "inc", "src/include", "src", "lib", "src/lib",
              "library", "core", "crypto", "common", "public", "api"]:
        p = src_dir / c
        if p.is_dir() and (any(p.glob("*.h")) or any(p.glob("*/*.h"))):
            d = f"$SRC/{c}"
            if d not in dirs:
                dirs.append(d)

    # 过滤 private/internal + vendor/platform 目录
    dirs = [d for d in dirs if not any(
        skip in d.lower() for skip in ['/private', '/internal', '/detail', '/impl']
    ) and not any(
        f'/{vendor_dir}' in d or d.endswith(f'/{vendor_dir}')
        for vendor_dir in VENDOR_SKIP_DIRS
    )]
    return dirs if dirs else ["$SRC"]


def _map_headers_to_libs(template_data):
    header_to_pkg = {
        # 压缩
        "zlib.h": ("zlib1g-dev", "-lz"), "zstd.h": ("libzstd-dev", "-lzstd"),
        "lz4.h": ("liblz4-dev", "-llz4"), "lz4frame.h": ("liblz4-dev", "-llz4"),
        "bzlib.h": ("libbz2-dev", "-lbz2"), "lzma.h": ("liblzma-dev", "-llzma"),
        "brotli/decode.h": ("libbrotli-dev", "-lbrotlidec"),
        # 网络 / 抓包
        "pcap.h": ("libpcap-dev", "-lpcap"), "pcap/pcap.h": ("libpcap-dev", "-lpcap"),
        "curl/curl.h": ("libcurl4-openssl-dev", "-lcurl"),
        # 加密 / TLS
        "ssl.h": ("libssl-dev", "-lssl"), "openssl/ssl.h": ("libssl-dev", "-lssl"),
        "crypto.h": ("libssl-dev", "-lcrypto"), "openssl/crypto.h": ("libssl-dev", "-lcrypto"),
        # XML / 解析
        "xml2.h": ("libxml2-dev", "-lxml2"), "libxml/parser.h": ("libxml2-dev", "-lxml2"),
        "expat.h": ("libexpat1-dev", "-lexpat"),
        # 图像
        "jpeglib.h": ("libjpeg-dev", "-ljpeg"), "png.h": ("libpng-dev", "-lpng"),
        "tiffio.h": ("libtiff-dev", "-ltiff"),
        # 字体 / 文本整形（harfbuzz 依赖 freetype，缺 -lfreetype 会链接失败）
        "ft2build.h": ("libfreetype6-dev", "-lfreetype"),
        "freetype/freetype.h": ("libfreetype6-dev", "-lfreetype"),
        "hb.h": ("libharfbuzz-dev", "-lharfbuzz"), "harfbuzz/hb.h": ("libharfbuzz-dev", "-lharfbuzz"),
        # 其它常见
        "pthread.h": (None, "-lpthread"),
        "unicode/utypes.h": ("libicu-dev", "-licuuc"),
    }
    sys_deps, sys_libs = [], []
    seen_deps, seen_libs = set(), set()
    for inc in template_data.get("all_includes", []):
        header = inc.strip('<>"')
        if header in header_to_pkg:
            dep, lib = header_to_pkg[header]
            if dep and dep not in seen_deps:
                sys_deps.append(dep); seen_deps.add(dep)
            if lib and lib not in seen_libs:
                sys_libs.append(lib); seen_libs.add(lib)
    return {"sys_deps": " ".join(sys_deps) if sys_deps else "",
            "sys_libs": " ".join(sys_libs) if sys_libs else ""}


def _detect_cxx_standard(project, src_dir):
    """检测项目强制的 C++ 标准（从 Makefile.am, CMakeLists.txt, build.sh）

    返回:
        {
            "detected": "c++11" | "c++14" | "c++17" | None,
            "source": "Makefile.am" | "CMakeLists.txt" | "build.sh" | None,
            "allow_fdp": bool  # FuzzedDataProvider 是否可用（需要 C++14+）
        }
    """
    result = {"detected": None, "source": None, "allow_fdp": True}

    # 1. 检查 OSS-Fuzz 的 Makefile.am（最高优先级）
    oss_fuzz_makefile = src_dir / "oss-fuzz" / "Makefile.am"
    if oss_fuzz_makefile.exists():
        try:
            content = oss_fuzz_makefile.read_text(errors='ignore')
            match = re.search(r'-std=(c\+\+\d+|gnu\+\+\d+)', content)
            if match:
                std = match.group(1).replace('gnu++', 'c++')
                result["detected"] = std
                result["source"] = "oss-fuzz/Makefile.am"
                result["allow_fdp"] = std not in ['c++98', 'c++03', 'c++11']
                return result
        except Exception:
            pass

    # 2. 检查根目录 Makefile.am
    makefile_am = src_dir / "Makefile.am"
    if makefile_am.exists():
        try:
            content = makefile_am.read_text(errors='ignore')
            match = re.search(r'-std=(c\+\+\d+|gnu\+\+\d+)', content)
            if match:
                std = match.group(1).replace('gnu++', 'c++')
                result["detected"] = std
                result["source"] = "Makefile.am"
                result["allow_fdp"] = std not in ['c++98', 'c++03', 'c++11']
                return result
        except Exception:
            pass

    # 3. 检查 CMakeLists.txt（CMAKE_CXX_STANDARD 或 set_property）
    cmake_file = src_dir / "CMakeLists.txt"
    if cmake_file.exists():
        try:
            content = cmake_file.read_text(errors='ignore')
            match = re.search(r'CMAKE_CXX_STANDARD\s+(\d+)', content)
            if match:
                std_num = match.group(1)
                result["detected"] = f"c++{std_num}"
                result["source"] = "CMakeLists.txt"
                result["allow_fdp"] = int(std_num) >= 14
                return result
            match = re.search(r'CXX_STANDARD\s+(\d+)', content)
            if match:
                std_num = match.group(1)
                result["detected"] = f"c++{std_num}"
                result["source"] = "CMakeLists.txt"
                result["allow_fdp"] = int(std_num) >= 14
                return result
        except Exception:
            pass

    # 4. 检查 OSS-Fuzz 的 build.sh（CXXFLAGS 覆盖）
    oss_fuzz_dir = OSS_FUZZ_DIR / "projects" / project
    build_sh = oss_fuzz_dir / "build.sh"
    if build_sh.exists():
        try:
            content = build_sh.read_text(errors='ignore')
            match = re.search(r'CXXFLAGS.*-std=(c\+\+\d+|gnu\+\+\d+)', content)
            if match:
                std = match.group(1).replace('gnu++', 'c++')
                result["detected"] = std
                result["source"] = "oss-fuzz/build.sh"
                result["allow_fdp"] = std not in ['c++98', 'c++03', 'c++11']
                return result
        except Exception:
            pass

    # 5. 未检测到显式配置，假定使用编译器默认
    result["detected"] = None
    result["source"] = None
    result["allow_fdp"] = True
    return result


def run_build_profile(project, template_data):
    """Step C: 构建 Profile 提取 → build_profile.json"""
    print("\n--- 构建 Profile ---")
    src_dir = SRC_DIR / project
    if not src_dir.exists():
        print(f"  错误: 源码目录 {src_dir} 不存在")
        return None

    profile = {"project": project, "build_system": "unknown",
               "include_dirs": [], "sys_deps": "", "sys_libs": "",
               "preferred_compiler": "clang"}

    build = _detect_build_system(src_dir)
    profile["build_system"] = build["type"]
    print(f"  构建系统: {build['type']}")

    if build["type"] == "autotools":
        _extract_from_autotools(src_dir, profile)
    elif build["type"] == "cmake":
        _extract_from_cmake(src_dir, profile)

    profile["include_dirs"] = _scan_include_dirs(src_dir, template_data)
    print(f"  include: {profile['include_dirs']}")

    lib_info = _map_headers_to_libs(template_data)
    profile["sys_deps"] = lib_info["sys_deps"] or "liblz4-dev libzstd-dev zlib1g-dev"
    profile["sys_libs"] = lib_info["sys_libs"] or "-llz4 -lzstd -lz"
    print(f"  sys_deps: {profile['sys_deps']}")
    print(f"  sys_libs: {profile['sys_libs']}")

    # 编译器偏好
    lang = template_data.get("dominant_lang", "c")
    cpp_count = c_count = 0
    for root, _, files in os.walk(str(src_dir)):
        if root.replace(str(src_dir), "").count(os.sep) > 3:
            continue
        for f in files:
            if f.endswith(('.cpp', '.cc', '.cxx')):
                cpp_count += 1
            elif f.endswith('.c'):
                c_count += 1
    profile["preferred_compiler"] = "clang++" if (lang == "cpp" or cpp_count > c_count * 0.3) else "clang"
    print(f"  compiler: {profile['preferred_compiler']}")

    # 检测 C++ 标准约束
    cxx_std = _detect_cxx_standard(project, src_dir)
    profile["cxx_standard"] = cxx_std["detected"]
    profile["cxx_std_source"] = cxx_std["source"]
    profile["allow_fuzzed_data_provider"] = cxx_std["allow_fdp"]
    if cxx_std["detected"]:
        print(f"  C++ 标准: {cxx_std['detected']} (来源: {cxx_std['source']})")
        if not cxx_std["allow_fdp"]:
            print(f"    ⚠️  FuzzedDataProvider 不可用（需要 C++14+）")

    out_path = intermediate_for(project) / "build_profile.json"
    out_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False))
    print(f"  → {out_path}")
    return profile


# ══════════════════════════════════════════════════════════════════════
# Section D: API 分类 & 打分
# ══════════════════════════════════════════════════════════════════════

def run_api_scoring(project, setup_data):
    """Step D: API 分类 & 打分 → scored.json"""
    print("\n--- API 打分 ---")

    untested_set = set(setup_data.get("untested_apis", []))
    tested_map = {t["name"]: t.get("drivers", []) for t in setup_data.get("tested_apis", [])}

    peer_usage = {}
    for pdp in setup_data.get("peer_driver_patterns", []):
        for api in pdp.get("apis", []):
            peer_usage[api] = peer_usage.get(api, 0) + 1

    # api_enrich 富化元数据（signature/params/... 来自 Q6 的 all_apis）
    meta_map = {e["name"]: e for e in setup_data.get("all_apis", []) if e.get("name")}

    scored = []
    for entry in setup_data.get("all_apis", []):
        name = entry["name"]
        if not name:
            continue
        is_untested = name in untested_set
        is_tested = name in tested_map
        pu = peer_usage.get(name, 0)

        meta = meta_map.get(name, {})
        signature = meta.get("signature", "")
        params = meta.get("params", []) or []
        description = meta.get("description", "")
        has_info = bool(signature)
        # 软加分：信息完整度只在同层内提升排序，刻意小于 untested(+15)
        info_bonus = min(
            (4 if signature else 0) + (3 if params else 0) + (2 if description else 0),
            9,
        )

        total = pu * 1 + (15 if is_untested else 0) + info_bonus
        scored.append({
            "api": name, "peer_usage_score": pu,
            "already_fuzzed": is_tested, "untested": is_untested,
            "total_score": max(total, 0), "peers": [],
            "existing_drivers": tested_map.get(name, []),
            # P1 #6：接入 setup 的 api_dependencies（共现关系，focus 规则2 用）
            "dependencies": setup_data.get("api_dependencies", {}).get(name, []),
            # api_enrich 富化字段（未富化项目 / 无 Neo4j 时为空 → has_info=False）
            "signature": signature,
            "return_type": meta.get("return_type", ""),
            "params": params,
            "param_count": meta.get("param_count", 0),
            "header": meta.get("header", ""),
            "header_path": meta.get("header_path", ""),
            "description": description,
            "desc_source": meta.get("desc_source", ""),
            "has_info": has_info,
        })

    scored.sort(key=lambda x: x["total_score"], reverse=True)
    unfuzzed = [s for s in scored if not s["already_fuzzed"]]
    fuzzed = [s for s in scored if s["already_fuzzed"]]

    output = {
        "project": project,
        "scenario": setup_data.get("scenarios", [])[0]["name"] if setup_data.get("scenarios") else "unknown",
        "scenario_desc": setup_data.get("scenarios", [])[0]["description"] if setup_data.get("scenarios") else "",
        "peer_projects": setup_data.get("peer_projects", []),
        "crash_stats": {
            "own_crashes": len(setup_data.get("own_crashes", [])),
            "own_drivers": len(setup_data.get("own_drivers", [])),
            "untested_apis": len(setup_data.get("untested_apis", [])),
            "tested_apis": len(setup_data.get("tested_apis", [])),
        },
        "scored_apis": scored,
        "top_targets": [s for s in scored if s["total_score"] > 0][:20],
        "unfuzzed_targets": unfuzzed[:50],
        "fuzzed_targets": fuzzed[:30],
    }

    out_file = intermediate_for(project) / "scored.json"
    with open(out_file, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"  untested: {len(unfuzzed)} 个 | tested: {len(fuzzed)} 个")
    print(f"  → {out_file}")
    return output


# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python step1_prepare.py <project_name>")
        sys.exit(1)

    project = sys.argv[1]
    os.makedirs(INTERMEDIATE_DIR, exist_ok=True)
    os.makedirs(SRC_DIR, exist_ok=True)
    proj_dir = intermediate_for(project)

    print(f"[Step1] 开始为 {project} 收集情报...")

    # 源码就绪 (non-fatal): 早于 B/C/step2 —— 它们都依赖 source_code/<project>。
    # 此前 clone 只在 step3 触发，导致新项目首跑时 step2 因源码缺失退出（total=0）。
    # 克隆失败不致命：A 段图谱情报不依赖源码，且 step3 仍有兜底调用。
    try:
        if agent_main.ensure_source_code(project):
            print(f"  [ensure_source] source_code/{project} 就绪")
        else:
            print(f"  [ensure_source] ⚠️ source_code/{project} 缺失且克隆失败，"
                  f"B/C/step2 可能降级，继续收集图谱情报...")
    except Exception as e:
        print(f"  [ensure_source] ⚠️ 克隆异常: {e}，继续...")

    # A: 图谱情报 (fatal)
    try:
        setup_data = run_graph_setup(project)
    except Exception as e:
        print(f"[ERROR] 图谱情报查询失败: {e}")
        sys.exit(1)

    # B: 模板提取 (non-fatal)
    try:
        template_data = run_template_extraction(project, setup_data)
    except Exception as e:
        print(f"[WARN] 模板提取失败: {e}")
        template_data = {}

    # C: 构建 Profile (non-fatal)
    try:
        run_build_profile(project, template_data)
    except Exception as e:
        print(f"[WARN] 构建 Profile 失败: {e}")

    # D: API 打分 (non-fatal)
    try:
        run_api_scoring(project, setup_data)
    except Exception as e:
        print(f"[WARN] API 打分失败: {e}")

    # 汇总
    print(f"\n[Step1] {project} 情报就绪 → {proj_dir}/")
    for f in sorted(proj_dir.glob("*.json")):
        print(f"  {f.name}")


if __name__ == "__main__":
    main()