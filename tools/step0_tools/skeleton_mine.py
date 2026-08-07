#!/usr/bin/env python3
"""
skeleton_mine.py — Phase 6: 从 KG CALLS 边 + LLM role 标注挖骨架序列

输入：
  _shared/role_dataset.jsonl  — driver→api 调用边（带 order/order_last，add_call_order v3 产出）
  _shared/role_labels.jsonl   — API → role 标注（role_annotate 产出）

输出：
  _shared/skeletons.json      — 骨架池（§4.1 schema）

骨架构造（§2.2）：
  按 driver 聚合 CALLS 边 → 按 order_last 升序 → 映射 role → 剔除 query/unknown → 折叠连续重复
  driver 丢弃阈值：unknown 占比 > 1/3 或 剔除后长度 < 4
  顺序：先剔除再折叠（不能颠倒，否则 configure,unknown,configure 折不掉）

骨架池去重：相同角色序列合并为一条，统计 support_drivers/support_projects/scenarios/
  slot_multiplicity（折叠前每角色典型出现次数的 [min,max]）/scenario_confidence/
  single_lib_dominated/source_enrichment_rate。
"""
import sys
import json
from pathlib import Path
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config import shared_dir, ROLES, ORDER_FIELD
from contracts.skeletons import save_skeletons, save_scenario, validate_skeletons, validate_scenario

ROLE_DATASET = shared_dir() / "role_dataset.jsonl"
ROLE_LABELS = shared_dir() / "role_labels.jsonl"

# 骨架进序列的角色（query/unknown 不进）
SEQ_ROLES = ROLES  # create/configure/data_sink/process/destroy
DISCARD_ROLES = ("query", "unknown")


def _load_role_labels() -> dict[str, str]:
    """加载 role_labels.jsonl → {cache_key-less: (project, api) → role}。

    role_labels.jsonl 每行有 cache_key/api/project/role。按 (project, api) 索引
    （同 API 名在不同项目可能是不同函数，§8.4 反面教材 2）。
    """
    labels: dict[tuple[str, str], str] = {}
    if not ROLE_LABELS.is_file():
        print(f"[skeleton_mine] 警告: {ROLE_LABELS} 不存在，全部 API 标 unknown")
        return labels
    for line in ROLE_LABELS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            proj = rec.get("project", "")
            api = rec.get("api", "")
            role = rec.get("role", "unknown")
            if proj and api:
                labels[(proj, api)] = role
        except json.JSONDecodeError:
            continue
    print(f"[skeleton_mine] 加载 {len(labels)} 条 role 标注")
    return labels


def _load_edges() -> list[dict]:
    """加载 role_dataset.jsonl 的调用边。"""
    edges = []
    for line in ROLE_DATASET.read_text(encoding="utf-8").splitlines():
        if line.strip():
            edges.append(json.loads(line))
    print(f"[skeleton_mine] 加载 {len(edges)} 条调用边")
    return edges


def _group_by_driver(edges: list[dict]) -> dict[tuple, list[dict]]:
    """按 (project, driver) 聚合边。"""
    by_driver: dict[tuple, list[dict]] = defaultdict(list)
    for e in edges:
        key = (e.get("project", ""), e.get("driver", ""))
        by_driver[key].append(e)
    return by_driver


def _build_skeleton(edges: list[dict], labels: dict[tuple[str, str], str]) -> tuple[list[str], dict]:
    """从 driver 的 CALLS 边构造骨架序列。

    返回 (skeleton, stats) where skeleton 是角色列表，stats 含 discarded 信息。
    按 §2.2：order_last 升序 → 映射 role → 剔除 query/unknown → 折叠连续重复。
    """
    # 1. 按 order_last 升序排（§2.2: 必须用 order_last 不是 order）
    sorted_edges = sorted(edges, key=lambda e: e.get("order_last", 0))

    # 2. 映射 role（按 (project, api) 查 labels；未标 → unknown）
    project = edges[0].get("project", "") if edges else ""
    role_seq_with_api = []  # [(role, api), ...] 保留 api 用于 slot_multiplicity
    n_unknown = 0
    for e in sorted_edges:
        api = e.get("api", "")
        role = labels.get((project, api), "unknown")
        role_seq_with_api.append((role, api))
        if role == "unknown":
            n_unknown += 1

    stats = {
        "n_edges": len(edges),
        "n_unknown": n_unknown,
        "unknown_ratio": n_unknown / len(edges) if edges else 0,
    }

    # 3. driver 丢弃阈值（§2.2）：unknown 占比 > 1/3 或 剔除后长度 < 4
    if stats["unknown_ratio"] > 1/3:
        return [], {**stats, "discarded": "unknown_ratio_too_high"}

    # 剔除 query/unknown（§2.2: 先剔除再折叠，不能颠倒）
    filtered = [(r, a) for r, a in role_seq_with_api if r in SEQ_ROLES]
    if len(filtered) < 4:
        return [], {**stats, "discarded": "too_short_after_filter", "len_after": len(filtered)}

    # 4. 折叠连续重复（create,configure,configure,decode → create,configure,decode）
    skeleton_roles = []
    slot_multiplicity_count = Counter()  # 折叠前每角色出现次数（用于 slot_multiplicity）
    prev_role = None
    for role, _ in filtered:
        slot_multiplicity_count[role] += 1
        if role != prev_role:
            skeleton_roles.append(role)
            prev_role = role

    return skeleton_roles, {**stats, "slot_multiplicity_count": dict(slot_multiplicity_count)}


def _build_skeletons_json(skeletons_by_shape: dict, project_scenarios: dict) -> dict:
    """把按形状分组的骨架构造成 skeletons.json dict（§4.1 schema）。"""
    skeletons_list = []
    for sid_idx, (shape, instances) in enumerate(
        sorted(skeletons_by_shape.items(), key=lambda x: -len(x[1])), start=1
    ):
        skel_id = f"sk_{sid_idx:04d}"
        support_drivers_n = len(instances)
        projects = sorted({inst["project"] for inst in instances})
        scenarios_counter = Counter()
        for inst in instances:
            sc = inst.get("scenario", "unknown")
            scenarios_counter[sc] += 1

        # scenario_confidence（§2.5）：按可用 driver 数分档
        total_usable = sum(scenarios_counter.values())
        if total_usable >= 20:
            confidence = "normal"
        elif total_usable >= 10:
            confidence = "low-confidence"
        else:
            confidence = "not-used"

        # single_lib_dominated：支撑 driver 全来自一个项目
        single_lib = len(projects) == 1

        # slot_multiplicity：每角色在折叠前的 [min, max] 出现次数
        slot_mult = {}
        for role in set(shape):
            counts = [inst.get("_slot_count", {}).get(role, 0) for inst in instances]
            counts = [c for c in counts if c > 0]
            if counts:
                slot_mult[role] = [min(counts), max(counts)]

        # source_enrichment_rate：支撑项目的平均富化率（用 signature 有无近似）
        skeletons_list.append({
            "id": skel_id,
            "sequence": list(shape),
            "support_drivers": support_drivers_n,
            "support_projects": projects,
            "scenarios": dict(scenarios_counter),
            "scenario_confidence": confidence,
            "single_lib_dominated": single_lib,
            "slot_multiplicity": slot_mult,
            "example_drivers": [f"{inst['project']}/{inst['driver']}" for inst in instances[:3]],
            "source_enrichment_rate": 0.9,  # 占位，精确值需查 KG api_enrich（暂近似）
        })

    return {
        "vocab_version": "v4",
        "order_field": ORDER_FIELD,
        "skeletons": skeletons_list,
    }


def _write_scenario_files(skeletons_data: dict, all_instances: list[dict],
                          edges: list[dict]) -> None:
    """为每个场景写 _shared/scenario/<场景>.json（§4.2 schema）。

    从 skeleton 实例 + 调用边推导场景级统计：
      - usable_drivers: 边数 ≥4 的 driver 数（§2.5 判定）
      - confidence: normal(≥20) / low-confidence(10-19) / not-used(<10)
      - project_distribution: {project: driver_count}
      - peer_projects_ranked: 按 driver_count 降序（§4.2: 不是 crash_count）
      - skeleton_ids: 该场景下出现的骨架 id
      - data_strategy_distribution: 占位（需 _classify_data_strategy，暂留空）
    """
    from collections import Counter

    # 按 (project, driver) 聚合边数
    drv_edges = Counter((e.get("project", ""), e.get("driver", "")) for e in edges)
    # 按 scenario 分组 driver
    scen_drivers: dict[str, list[tuple]] = defaultdict(list)
    for (proj, drv), n in drv_edges.items():
        # 找 scenario：从 edges 里找该 (proj,drv) 的 scenario
        sc = next((e.get("scenario", "unknown") for e in edges
                   if e.get("project") == proj and e.get("driver") == drv), "unknown")
        scen_drivers[sc].append((proj, drv, n))

    # 骨架按 scenario 索引
    scen_skel_ids: dict[str, list[str]] = defaultdict(list)
    for sk in skeletons_data.get("skeletons", []):
        for sc, n in sk.get("scenarios", {}).items():
            if n > 0:
                scen_skel_ids[sc].append(sk["id"])

    for sc, drivers in scen_drivers.items():
        usable = [d for d in drivers if d[2] >= 4]
        n_usable = len(usable)
        if n_usable >= 20:
            conf = "normal"
        elif n_usable >= 10:
            conf = "low-confidence"
        else:
            conf = "not-used"

        # project_distribution
        proj_dist = Counter(d[0] for d in drivers)
        single_lib = len(proj_dist) == 1 or (
            max(proj_dist.values()) / sum(proj_dist.values()) > 0.87)  # §2.5: 87% 单库主导

        # peer_projects_ranked: 按 driver_count 降序（§4.2: 不是 crash_count）
        peer_ranked = [p for p, _ in proj_dist.most_common()]

        scen_data = {
            "scenario": sc,
            "usable_drivers": n_usable,
            "confidence": conf,
            "single_lib_dominated": single_lib,
            "project_distribution": dict(proj_dist),
            "peer_projects_ranked": peer_ranked,
            "skeleton_ids": scen_skel_ids.get(sc, []),
            "data_strategy_distribution": {},  # 占位，需 _classify_data_strategy
        }
        issues = validate_scenario(scen_data, sc)
        if issues:
            print(f"[skeleton_mine] ⚠️ scenario {sc} 校验: {issues[:3]}")
        save_scenario(sc, scen_data)
    print(f"[skeleton_mine] 写 {len(scen_drivers)} 个 scenario 文件 → {shared_dir() / 'scenario'}")


def main():
    if not ROLE_DATASET.is_file():
        sys.exit(f"输入不存在: {ROLE_DATASET}")

    labels = _load_role_labels()
    edges = _load_edges()
    by_driver = _group_by_driver(edges)
    print(f"[skeleton_mine] {len(by_driver)} 个 driver")

    # 构造每个 driver 的骨架
    skeletons_by_shape: dict[tuple, list[dict]] = defaultdict(list)
    n_discarded = 0
    discard_reasons = Counter()
    for (project, driver), drv_edges in by_driver.items():
        skeleton, stats = _build_skeleton(drv_edges, labels)
        if not skeleton:
            n_discarded += 1
            discard_reasons[stats.get("discarded", "?")] += 1
            continue
        shape = tuple(skeleton)
        scenario = drv_edges[0].get("scenario", "unknown") if drv_edges else "unknown"
        skeletons_by_shape[shape].append({
            "project": project,
            "driver": driver,
            "scenario": scenario,
            "_slot_count": stats.get("slot_multiplicity_count", {}),
        })

    print(f"[skeleton_mine] 产出 {len(skeletons_by_shape)} 条唯一骨架 | "
          f"丢弃 {n_discarded} driver: {dict(discard_reasons)}")

    # 构造 skeletons.json
    project_scenarios = {}  # 占位
    data = _build_skeletons_json(skeletons_by_shape, project_scenarios)

    # 校验并写盘
    issues = validate_skeletons(data)
    if issues:
        print(f"[skeleton_mine] ⚠️ schema 校验问题:")
        for i in issues[:10]:
            print(f"  - {i}")
    save_skeletons(data)
    print(f"[skeleton_mine] → {shared_dir() / 'skeletons.json'}")
    print(f"  骨架池: {len(data['skeletons'])} 条")

    # 写 scenario 文件（§4.2）
    all_instances = []
    for shape, insts in skeletons_by_shape.items():
        all_instances.extend(insts)
    _write_scenario_files(data, all_instances, edges)

    if data["skeletons"]:
        top = data["skeletons"][:5]
        print(f"  top 5 by support_drivers:")
        for s in top:
            print(f"    {s['id']} {s['sequence']} support={s['support_drivers']} "
                  f"projects={len(s['support_projects'])} conf={s['scenario_confidence']}")


if __name__ == "__main__":
    main()
