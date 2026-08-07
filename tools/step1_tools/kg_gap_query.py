#!/usr/bin/env python3
"""
kg_gap_query.py — 4.5 只读查询：算「被 driver 调用但无 order 边」的 API 缺口分布

只跑 MATCH，不改 KG。输出：
  - 全图 CALLS 边总数 / 有 order 的边数 / 缺口边数
  - 全图被调用 API 总数 / 有 order 的 API 数 / 完全无 order 的 API 数（缺口 API）
  - 按场景分布的缺口 API 数（指导 4.6 v3 改进优先级）
  - 按项目分布的缺口边数（前 20，定位 v3 要攻哪些项目）
  - 缺口 API 的失败模式抽样（5 条/项目，看是什么符号）

落盘报告到 _shared/kg_gap_report.txt，便于 4.6 参考。
"""
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE, shared_dir
from neo4j import GraphDatabase, basic_auth


def _run(session, query, **params):
    return [dict(r) for r in session.run(query, **params)]


def main():
    if not NEO4J_PASSWORD:
        sys.exit("NEO4J_PASSWORD 未设置")

    drv = GraphDatabase.driver(NEO4J_URI, auth=basic_auth(NEO4J_USER, NEO4J_PASSWORD))
    lines = []
    A = lines.append

    with drv.session(database=NEO4J_DATABASE) as s:
        # ── 1. 全图边/API 总览（区分项目 API vs libc 符号）──
        # 项目 API = (lib)-[:HAS_API]->(a)，libc/外部符号不在 HAS_API 集合
        overview = _run(s, """
            MATCH (lib:Library)-[:HAS_DRIVER]->(d)-[c:CALLS]->(a)
            WHERE a:CAPI OR a:API
            WITH c, lib, a,
                 EXISTS((lib)-[:HAS_API]->(a)) AS is_proj_api
            RETURN count(c) AS total_edges,
                   count(DISTINCT [lib.name, a.name]) AS total_apis,
                   sum(CASE WHEN is_proj_api THEN 1 ELSE 0 END) AS proj_api_edges,
                   sum(CASE WHEN is_proj_api THEN 0 ELSE 1 END) AS nonproj_edges
        """)[0]
        ordered = _run(s, """
            MATCH (lib:Library)-[:HAS_DRIVER]->(d)-[c:CALLS]->(a)
            WHERE (a:CAPI OR a:API) AND c.order IS NOT NULL
            WITH c, lib, a, EXISTS((lib)-[:HAS_API]->(a)) AS is_proj_api
            RETURN count(c) AS ordered_edges,
                   count(DISTINCT [lib.name, a.name]) AS ordered_apis,
                   sum(CASE WHEN is_proj_api THEN 1 ELSE 0 END) AS ord_proj_edges
        """)[0]

        total_e = overview["total_edges"]
        ord_e = ordered["ordered_edges"]
        total_a = overview["total_apis"]
        ord_a = ordered["ordered_apis"]
        gap_e = total_e - ord_e
        gap_a = total_a - ord_a
        proj_e = overview["proj_api_edges"]
        nonproj_e = overview["nonproj_edges"]
        ord_proj_e = ordered["ord_proj_edges"]
        gap_proj_e = proj_e - ord_proj_e

        A("=" * 60)
        A("KG 缺口报告（4.5）：被调用但无 order 边的 API")
        A("=" * 60)
        A("")
        A("【1. 全图总览】")
        A(f"  CALLS 边总数:                {total_e}")
        A(f"    其中项目 API 边:           {proj_e} ({proj_e/total_e*100:.1f}%)")
        A(f"    其中 libc/外部符号边:      {nonproj_e} ({nonproj_e/total_e*100:.1f}%)  ← 非项目 API，v3 不需处理")
        A(f"  有 order 的边:               {ord_e} ({ord_e/total_e*100:.1f}%)")
        A(f"  无 order 的边（缺口）:       {gap_e} ({gap_e/total_e*100:.1f}%)")
        A("")
        A(f"  项目 API 边:                 {proj_e}")
        A(f"    有 order:                  {ord_proj_e} ({ord_proj_e/proj_e*100:.1f}%)  ← v3 真正要提升的")
        A(f"    无 order（真缺口）:         {gap_proj_e} ({gap_proj_e/proj_e*100:.1f}%)")
        A("")
        A(f"  被调用 API 总数（去重）:      {total_a}")
        A(f"  有 order 边的 API:           {ord_a} ({ord_a/total_a*100:.1f}%)  ← role_apis.jsonl 当前规模")
        A(f"  完全无 order 的 API:         {gap_a} ({gap_a/total_a*100:.1f}%)  ← 含 libc 符号，真缺口更小")

        # ── 2. 按场景分布（只算项目 API 缺口）──
        A("")
        A("【2. 按场景分布的项目 API 缺口（v3 优先级）】")
        scen_gap = _run(s, """
            MATCH (lib:Library)-[:HAS_DRIVER]->(d)-[c:CALLS]->(a)
            WHERE (a:CAPI OR a:API) AND EXISTS((lib)-[:HAS_API]->(a))
            WITH lib, a,
                 count(c) AS tc,
                 count(CASE WHEN c.order IS NOT NULL THEN 1 END) AS oc
            WHERE oc = 0
            MATCH (lib)-[:APPLY_TO]->(sc:Scenario)
            RETURN sc.name AS scenario, count(DISTINCT [lib.name, a.name]) AS gap_apis
            ORDER BY gap_apis DESC
        """)
        A(f"  {'场景':30s} {'缺口项目API':>12s}")
        for r in scen_gap:
            A(f"  {r['scenario']:30s} {r['gap_apis']:>12d}")

        # ── 3. 按项目分布（项目 API 缺口边数前 20）──
        A("")
        A("【3. 按项目分布的项目 API 缺口边数（前 20，v3 优先攻）】")
        proj_gap = _run(s, """
            MATCH (lib:Library)-[:HAS_DRIVER]->(d)-[c:CALLS]->(a)
            WHERE (a:CAPI OR a:API) AND EXISTS((lib)-[:HAS_API]->(a))
            WITH lib,
                 count(c) AS total_edges,
                 count(CASE WHEN c.order IS NOT NULL THEN 1 END) AS ordered_edges
            RETURN lib.name AS project,
                   total_edges,
                   ordered_edges,
                   total_edges - ordered_edges AS gap_edges
            ORDER BY gap_edges DESC
            LIMIT 20
        """)
        A(f"  {'项目':28s} {'总边':>6s} {'有order':>8s} {'缺口':>6s} {'覆盖率':>7s}")
        for r in proj_gap:
            cov = r["ordered_edges"] / r["total_edges"] * 100 if r["total_edges"] else 0
            A(f"  {r['project']:28s} {r['total_edges']:>6d} {r['ordered_edges']:>8d} "
              f"{r['gap_edges']:>6d} {cov:>6.1f}%")

        # ── 4. 缺口项目 API 抽样（看 v3 要攻的失败模式，过滤 libc）──
        A("")
        A("【4. 缺口项目 API 抽样（已过滤 libc/外部符号）】")
        top_proj = [r["project"] for r in proj_gap[:5]]
        for proj in top_proj:
            samples = _run(s, """
                MATCH (lib:Library {name: $proj})-[:HAS_DRIVER]->(d)-[c:CALLS]->(a)
                WHERE (a:CAPI OR a:API) AND EXISTS((lib)-[:HAS_API]->(a))
                WITH lib, a,
                     count(c) AS tc,
                     count(CASE WHEN c.order IS NOT NULL THEN 1 END) AS oc
                WHERE oc = 0
                RETURN a.name AS api, a.lang AS lang, a.signature AS signature
                LIMIT 5
            """, proj=proj)
            A(f"\n  [{proj}] 缺口项目 API 抽样:")
            for sample in samples:
                sig = (sample["signature"] or "")[:80]
                A(f"    {sample['api']:40s} [{sample['lang'] or '?'}] {sig}")

    drv.close()

    report = "\n".join(lines)
    out = shared_dir() / "kg_gap_report.txt"
    out.write_text(report, encoding="utf-8")
    print(report)
    print(f"\n→ {out}")


if __name__ == "__main__":
    main()
