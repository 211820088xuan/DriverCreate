#!/usr/bin/env python3
"""
export_role_dataset.py — 导出 role 标注数据集 + 阶段 0 体检报告

放到 driver_create/tools/ 下跑（需要能 import config）：
    cd /root/gyx/driver_create
    python3 tools/export_role_dataset.py

产出（默认写到 artifacts/intermediate/_shared/）：
    role_dataset.jsonl   每行一个 (driver, api) 调用边，带 order + API 富化字段
    role_apis.jsonl      每行一个去重后的 API，带富化字段（标注脚本的输入）
    phase0_report.txt    阶段 0 三份体检报告

只读图谱，不写任何东西。
"""
import os
import sys
import json
from pathlib import Path
from collections import Counter, defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config import (NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE,
                    INTERMEDIATE_DIR)
from neo4j import GraphDatabase, basic_auth

OUT_DIR = INTERMEDIATE_DIR / "_shared"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# ── 1. 带 order 的调用边（这就是「2895」的来源）────────────────────
Q_EDGES = """
MATCH (lib:Library)-[:HAS_DRIVER]->(d)-[c:CALLS]->(a)
WHERE c.order IS NOT NULL AND (a:CAPI OR a:API)
RETURN lib.name        AS project,
       d.name          AS driver,
       a.name          AS api,
       c.order         AS ord,
       c.order_last    AS ord_last
"""

# ── 2. API 富化属性（去重后按 (project, api) 取）───────────────────
Q_APIS = """
MATCH (lib:Library)-[:HAS_API]->(a)
WHERE (a:CAPI OR a:API)
RETURN lib.name AS project, a.name AS name, a.lang AS lang,
       a.signature AS signature, a.return_type AS return_type,
       a.params AS params, a.param_count AS param_count,
       a.header AS header, a.description AS description,
       a.desc_source AS desc_source
"""

# ── 3. 库 → 场景 ──────────────────────────────────────────────────
Q_SCENARIO = """
MATCH (lib:Library)-[:APPLY_TO]->(s:Scenario)
RETURN lib.name AS project, collect(s.name) AS scenarios
"""


def main():
    if not NEO4J_PASSWORD:
        sys.exit("NEO4J_PASSWORD 未设置")
    drv = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))

    with drv.session(database=NEO4J_DATABASE) as s:
        print("[1/3] 查场景...")
        scen = {r["project"]: (r["scenarios"] or ["unknown"])[0]
                for r in s.run(Q_SCENARIO)}

        print("[2/3] 查带 order 的调用边...")
        edges = [dict(r) for r in s.run(Q_EDGES)]
        print(f"      {len(edges)} 条边")

        # 只查涉及到的库，省内存：先收集有边的 project
        live_projects = {e["project"] for e in edges}
        print("[3/3] 查 API 富化属性...")
        api_meta = {}
        for r in s.run(Q_APIS):
            if r["project"] not in live_projects:
                continue
            api_meta[(r["project"], r["name"])] = {
                "lang": r["lang"] or "",
                "signature": r["signature"] or "",
                "return_type": r["return_type"] or "",
                "params": r["params"] or [],
                "param_count": r["param_count"] or 0,
                "header": r["header"] or "",
                "description": r["description"] or "",
                "desc_source": r["desc_source"] or "",
            }
        print(f"      {len(api_meta)} 个 API（限有边的 {len(live_projects)} 个库）")
    drv.close()

    # ── 写 role_dataset.jsonl（边级）──────────────────────────────
    empty = {"lang": "", "signature": "", "return_type": "", "params": [],
             "param_count": 0, "header": "", "description": "", "desc_source": ""}
    with open(OUT_DIR / "role_dataset.jsonl", "w", encoding="utf-8") as f:
        for e in edges:
            m = api_meta.get((e["project"], e["api"]), empty)
            f.write(json.dumps({
                "project": e["project"],
                "scenario": scen.get(e["project"], "unknown"),
                "driver": e["driver"],
                "api": e["api"],
                "order": e["ord"],
                "order_last": e["ord_last"],
                **m,
            }, ensure_ascii=False) + "\n")

    # ── 写 role_apis.jsonl（API 级去重，标注脚本的输入）────────────
    api_drivers = defaultdict(set)
    for e in edges:
        api_drivers[(e["project"], e["api"])].add(e["driver"])
    with open(OUT_DIR / "role_apis.jsonl", "w", encoding="utf-8") as f:
        for (proj, api), drivers in sorted(api_drivers.items()):
            m = api_meta.get((proj, api), empty)
            f.write(json.dumps({
                "project": proj,
                "scenario": scen.get(proj, "unknown"),
                "api": api,
                "called_by_n_drivers": len(drivers),   # 频次分档用
                **m,
            }, ensure_ascii=False) + "\n")

    # ══ 阶段 0 体检报告 ══════════════════════════════════════════
    lines = []
    A = lines.append
    n_api = len(api_drivers)
    A(f"待标注 API（去重）: {n_api}    调用边: {len(edges)}    库: {len(live_projects)}")

    A("\n【报告1】富化字段缺失分布")
    for fld in ("signature", "description", "params", "header"):
        n = sum(1 for k in api_drivers
                if api_meta.get(k, empty).get(fld))
        A(f"  {fld:12s} {n}/{n_api} = {n/max(n_api,1)*100:.1f}%")
    A("  按库看缺失最严重的 15 个（有边 API 数 >= 10）:")
    per_lib = defaultdict(lambda: [0, 0])
    for (proj, api) in api_drivers:
        per_lib[proj][0] += 1
        if api_meta.get((proj, api), empty)["signature"]:
            per_lib[proj][1] += 1
    worst = sorted((v[1]/v[0], p, v) for p, v in per_lib.items() if v[0] >= 10)[:15]
    for rate, p, v in worst:
        A(f"    {p:28s} 有签名 {v[1]:4d}/{v[0]:4d} = {rate*100:5.1f}%")

    A("\n【报告2】signature 格式勘察（C 与 C++ 各抽 10 条）")
    for want_cpp in (False, True):
        A(f"  --- {'C++ 疑似（含 :: 或 lang=cpp）' if want_cpp else 'C'} ---")
        shown = 0
        for (proj, api) in api_drivers:
            m = api_meta.get((proj, api), empty)
            sig = m["signature"]
            if not sig:
                continue
            is_cpp = "::" in sig or m["lang"] in ("cpp", "c++", "cxx")
            if is_cpp != want_cpp:
                continue
            A(f"    [{proj}] {sig[:150]}")
            A(f"        ret={m['return_type']!r} param_count={m['param_count']} "
              f"desc_source={m['desc_source']!r}")
            shown += 1
            if shown >= 10:
                break
        if shown == 0:
            A("    （没有样本）")

    A("\n【报告3】按场景的可用样本量（边数 >= 4 才算可用 driver）")
    drv_edges = Counter((e["project"], e["driver"]) for e in edges)
    scen_total, scen_ok = Counter(), Counter()
    for (proj, d), n in drv_edges.items():
        sc = scen.get(proj, "unknown")
        scen_total[sc] += 1
        if n >= 4:
            scen_ok[sc] += 1
    A(f"  {'场景':26s} {'可用':>5s} {'有边':>5s}  判定")
    for sc, tot in scen_total.most_common():
        ok = scen_ok[sc]
        verdict = "正常" if ok >= 20 else ("low-confidence" if ok >= 10 else "不进 skeletons")
        A(f"  {sc:26s} {ok:5d} {tot:5d}  {verdict}")

    A("\n  每 driver 边数分布（全局）:")
    A("    " + str(sorted(Counter(drv_edges.values()).items())))

    A("\n【附】调用频次分档（标定用）")
    A("    " + str(sorted(Counter(len(v) for v in api_drivers.values()).items())[:15]))

    report = "\n".join(lines)
    (OUT_DIR / "phase0_report.txt").write_text(report, encoding="utf-8")
    print("\n" + report)
    print(f"\n→ {OUT_DIR}/role_dataset.jsonl / role_apis.jsonl / phase0_report.txt")


if __name__ == "__main__":
    main()