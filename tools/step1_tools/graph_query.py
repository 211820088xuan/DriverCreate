#!/usr/bin/env python3
"""Step1 Section A：图谱情报查询（Neo4j）→ setup.json。唯一的 Neo4j 层。"""
# 从 step1_prepare.py 阶段2 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE,
    SRC_DIR, OSS_FUZZ_DIR,
    intermediate_for,
)

# ─── Neo4j 可选 ────────────────────────────────────────────────────
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
