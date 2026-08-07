#!/usr/bin/env python3
"""
plan_gen.py — Phase 6b: 三模式 plan 生成（focus / peer / cross）

输入：
  _shared/skeletons.json          — 骨架池（skeleton_mine 产出）
  _shared/scenario/<场景>.json     — 场景级统计
  _shared/role_labels.jsonl       — API → role 标注（槽位填充用）
  <project>/scored.json           — 本项目 API 池 + 签名 + 富化字段

输出：
  <project>/plan_focus.json / plan_peer.json / plan_cross.json（§4.3 schema）

三模式（§7）：
  focus: 本项目已有 driver 的真实序列，往里插未调用过的 API（规则 1 configure + 规则 2 同角色替代）
  peer:  骨架池中 d(k)==2 的（结构距离最近但没做过），按 support_drivers 降序取前 N
  cross: 骨架池中 d(k)≥3 的（结构最远），同 peer 逻辑

槽位填充（§7.2）：
  C 项目：签名规则快速筛（低召回 ~19%），未命中过 LLM（_llm_fill_missing_roles 已实现）
  C++ 方法（signature 含 ::）：跳过签名规则，直接走 role_labels（LLM 标注）
  填不满任何一个槽 → 整条跳过，记 skipped（§4.3 必须有）

距离计算：编辑距离 ≤1 用于「本项目已覆盖」判断（§2.3）；==2 peer；≥3 cross。
"""
import sys
import json
from pathlib import Path
from typing import Optional
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "step0_tools"))  # 便于 import role_annotate（已搬至 step0_tools）
from config import intermediate_for, MODES, ROLES, shared_dir
from plan_loader import save_plan, empty_plan, PLAN_VERSION
try:
    from role_annotate import _annotate_batch, BATCH_SIZE, FAST_MODEL, STRONG_MODEL, ROLE_LABELS_EXTENDED
except ImportError:
    _annotate_batch = None
from skeleton_loader import load_skeletons, load_scenario, skeleton_by_id


def _llm_fill_missing_roles(project: str, scored_apis: list[dict],
                            role_labels: dict[str, str]) -> dict[str, str]:
    """对 role_labels 未覆盖的 API 批量调 LLM 标注角色，结果追加缓存到 role_labels.jsonl。

    复用 role_annotate 的 _annotate_batch（分批 + 完整性校验）+ _append_cache。
    role_labels.jsonl 按 (project, api) 索引（项目内 api 名唯一）。
    """
    if not scored_apis:
        return role_labels
    # 找未标注 API
    missing = [a for a in scored_apis if a.get("api") and a["api"] not in role_labels]
    if not missing:
        return role_labels
    try:
        from role_annotate import _annotate_batch, _append_cache, BATCH_SIZE, FAST_MODEL, STRONG_MODEL
    except ImportError:
        print(f"  [llm_fill] 无法 import role_annotate，跳过 LLM 填槽（{len(missing)} 个未标注）")
        return role_labels

    print(f"  [llm_fill] {project}: {len(missing)} 个 API 未标注，批量调 LLM（批 {BATCH_SIZE}）")
    # 批量标注：fast 模型先跑，incomplete 的用 strong 兜底
    all_results = []
    for bi in range(0, len(missing), BATCH_SIZE):
        batch = missing[bi: bi + BATCH_SIZE]
        # 补 project 字段（_annotate_batch 要 project）
        for e in batch:
            e.setdefault("project", project)
        results = _annotate_batch(batch, FAST_MODEL)
        # fast 的 incomplete 用 strong 重跑（_annotate_batch 返回长度恒=batch，用 incomplete 标记判断）
        incomplete_apis = {r["api"] for r in results if r.get("incomplete")}
        if incomplete_apis:
            retry = [e for e in batch if e["api"] in incomplete_apis]
            results2 = _annotate_batch(retry, STRONG_MODEL)
            # strong 的结果覆盖 incomplete 的
            by_api = {r["api"]: r for r in results2 if not r.get("incomplete")}
            results = [by_api.get(r["api"], r) if r.get("incomplete") else r for r in results]
        all_results.extend(results)

    # 追加到 role_labels.jsonl（plan_gen 的 _load_role_labels 读这个文件）
    if all_results:
        out_path = shared_dir() / "role_labels.jsonl"
        with open(out_path, "a", encoding="utf-8") as f:
            for r in all_results:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        # 更新内存 role_labels
        for r in all_results:
            if r.get("role") in ROLES or r.get("role") == "query" or r.get("role") == "unknown":
                role_labels[r["api"]] = r["role"]
        print(f"  [llm_fill] {project}: LLM 标注 {len(all_results)} 个，已追加到 role_labels.jsonl")
    return role_labels


def _llm_fill_on_demand(project: str, batch: list[dict],
                        role_labels: dict[str, str]) -> None:
    """按需标一批 API（batch ≤ BATCH_SIZE），结果缓存到 role_labels.jsonl + 更新内存 role_labels。
    只标传入的 batch，不预标全 all_apis。槽位填不够时调。"""
    if not batch or _annotate_batch is None:
        return
    for e in batch:
        e.setdefault("project", project)
    results = _annotate_batch(batch, FAST_MODEL)
    # fast 的 incomplete 用 strong 兜底
    incomplete = {r["api"] for r in results if r.get("incomplete")}
    if incomplete:
        retry = [e for e in batch if e["api"] in incomplete]
        try:
            r2 = _annotate_batch(retry, STRONG_MODEL)
            by_api = {r["api"]: r for r in r2 if not r.get("incomplete")}
            results = [by_api.get(r["api"], r) if r.get("incomplete") else r
                       for r in results]
        except Exception as e:
            print(f"  [on_demand] {project} strong 兜底失败: {e}")
    # 缓存到 role_labels.jsonl + 更新内存
    out_path = shared_dir() / "role_labels.jsonl"
    with open(out_path, "a", encoding="utf-8") as f:
        for r in results:
            if r.get("role") in ROLE_LABELS_EXTENDED:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
                role_labels[r["api"]] = r["role"]


def _llm_fill_top_n(project: str, scored_apis: list[dict],
                    role_labels: dict[str, str], top_n: int = 200,
                    workers: int = 4) -> None:
    """混合方案：开头并发预标 scored top N 里签名规则没命中 + role_labels 没标的 API。

    只标 top N（最值得测的），不预标全 all_apis。
    create/configure/data_sink 由签名规则免费筛（不受 N 限制），此处只标 process/destroy/query。
    并发批量标（ThreadPoolExecutor），标完更新 role_labels（内存 + 文件）。
    """
    if _annotate_batch is None or not scored_apis:
        return
    # 按 total_score 降序取 top N
    sorted_apis = sorted(scored_apis, key=lambda a: a.get("total_score", 0), reverse=True)
    top = sorted_apis[:top_n]
    # 筛出"签名规则没命中 + role_labels 没标"的（C++ 方法 signature 含 :: 也算没命中，走 LLM）
    need_label = []
    for a in top:
        api_name = a.get("api", "")
        if not api_name or api_name in role_labels:
            continue
        sig = a.get("signature", "")
        if "::" not in sig and _sig_rule_role(a) is not None:
            continue  # 签名规则能判（create/configure/data_sink），不用 LLM
        a.setdefault("project", project)
        need_label.append(a)
    if not need_label:
        return
    # 切 batch，并发标
    batches = [need_label[i:i + BATCH_SIZE] for i in range(0, len(need_label), BATCH_SIZE)]
    print(f"  [top_n] {project}: top {len(top)} 中 {len(need_label)} 个待 LLM 标 "
          f"({len(batches)} batch, 并发 {workers})")
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _run_batch(batch):
        results = _annotate_batch(batch, FAST_MODEL)
        incomplete = {r["api"] for r in results if r.get("incomplete")}
        if incomplete:
            retry = [e for e in batch if e["api"] in incomplete]
            try:
                r2 = _annotate_batch(retry, STRONG_MODEL)
                by_api = {r["api"]: r for r in r2 if not r.get("incomplete")}
                results = [by_api.get(r["api"], r) if r.get("incomplete") else r
                           for r in results]
            except Exception as e:
                print(f"  [top_n] {project} strong 兜底失败: {e}")
        return results

    all_results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_run_batch, b): b for b in batches}
        done = 0
        for f in as_completed(futures):
            try:
                all_results.extend(f.result())
            except Exception as e:
                print(f"  [top_n] {project} batch 失败: {e}")
            done += 1
            if done % 5 == 0 or done == len(batches):
                print(f"  [top_n] {project}: {done}/{len(batches)} batch")
    # 写 role_labels.jsonl + 更新内存
    out_path = shared_dir() / "role_labels.jsonl"
    n_written = 0
    with open(out_path, "a", encoding="utf-8") as f:
        for r in all_results:
            if r.get("role") in ROLE_LABELS_EXTENDED:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
                role_labels[r["api"]] = r["role"]
                n_written += 1
    print(f"  [top_n] {project}: 标 {n_written} 个 → role_labels.jsonl")


# ── 编辑距离（Levenshtein）──
def _edit_distance(a: tuple, b: tuple) -> int:
    """两个角色序列的编辑距离。用 DP，序列长度 ≤20 够快。"""
    m, n = len(a), len(b)
    if m == 0: return n
    if n == 0: return m
    prev = list(range(n + 1))
    for i in range(1, m + 1):
        cur = [i] + [0] * n
        for j in range(1, n + 1):
            if a[i-1] == b[j-1]:
                cur[j] = prev[j-1]
            else:
                cur[j] = 1 + min(prev[j], cur[j-1], prev[j-1])
        prev = cur
    return prev[n]


def _min_distance_to_own(skel_seq: tuple, own_shapes: list[tuple]) -> int:
    """骨架到本项目现有形状集合的最小编辑距离。"""
    if not own_shapes:
        return len(skel_seq)  # 本项目无形状 → 距离=序列长度（视为最远）
    return min(_edit_distance(skel_seq, own) for own in own_shapes)


# ── 本项目现有骨架形状（从 role_dataset.jsonl + role_labels.jsonl 重建）──
def _project_own_shapes(project: str) -> list[tuple]:
    """重建本项目的 driver 骨架形状集合（与 skeleton_mine 同逻辑，但只本项目）。"""
    from config import shared_dir
    role_ds = shared_dir() / "role_dataset.jsonl"
    role_lb = shared_dir() / "role_labels.jsonl"
    if not role_ds.is_file() or not role_lb.is_file():
        return []

    # 加载 role 标注
    labels: dict[str, str] = {}  # api → role（本项目内同名 api 取第一个）
    for line in role_lb.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        rec = json.loads(line)
        if rec.get("project") == project:
            labels.setdefault(rec["api"], rec["role"])

    # 按 driver 聚合本项目边
    by_driver: dict[str, list[dict]] = defaultdict(list)
    for line in role_ds.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        e = json.loads(line)
        if e.get("project") == project:
            by_driver[e["driver"]].append(e)

    shapes = []
    for drv, edges in by_driver.items():
        sorted_edges = sorted(edges, key=lambda e: e.get("order_last", 0))
        role_seq = [labels.get(e["api"], "unknown") for e in sorted_edges]
        if sum(1 for r in role_seq if r == "unknown") / max(len(role_seq), 1) > 1/3:
            continue
        filtered = [r for r in role_seq if r in ROLES]
        if len(filtered) < 4:
            continue
        # 折叠连续重复
        skeleton = []
        prev = None
        for r in filtered:
            if r != prev:
                skeleton.append(r)
                prev = r
        shapes.append(tuple(skeleton))
    return shapes


# ── 槽位填充：签名规则快速筛（C 项目）──
# §7.2: 签名规则低召回（实测 19%），命中的直接采信，未命中需过 LLM（TODO）
def _sig_rule_role(api_entry: dict) -> Optional[str]:
    """用签名形状快速判 role。返回 None = 未命中（需 LLM）。

    只看签名形状（返回类型/参数类型/参数个数），不看 API 名关键词——
    名字语义交给 LLM（role_annotate），规则只做低精度高召回的形状筛。
    name 关键词判 role 是已否决的做法（get/read/next 大量命中 query 类，
    误判 process 会污染最上游的骨架形状数据）。

    规则（纯签名形状）：
    - 返回 handle 指针 + 参数少（≤2）→ create（工厂函数）
    - 首参 const void* + 有 size 参数 → data_sink（喂字节流）
    - 首参是 handle 指针 + 返回 int/void → configure（改对象状态）
    - 名字 shape 不判 destroy（free/destroy 只能靠名字，留给 LLM）
    """
    sig = api_entry.get("signature", "")
    ret = api_entry.get("return_type", "")
    params = api_entry.get("params", [])
    n_params = api_entry.get("param_count", 0)

    # create: 返回指针 + 参数少（工厂函数形状）
    if "*" in ret and n_params <= 2:
        return "create"

    # data_sink: 首参 const void* + 有 size 参数（喂字节流形状）
    if params:
        first = params[0].lower() if isinstance(params[0], str) else ""
        has_size = any("size" in p.lower() for p in params if isinstance(p, str))
        if "const void" in first and has_size:
            return "data_sink"

    # configure: 首参是 handle 指针 + 返回 int/void（改对象状态形状）
    if params and ret in ("int", "void", "unsigned int"):
        first = params[0].lower() if isinstance(params[0], str) else ""
        if "*" in first:
            return "configure"

    # destroy / process / query：签名形状无法区分，留给 LLM
    return None


def _load_role_labels(project: str) -> dict[str, str]:
    """从 _shared/role_labels.jsonl 加载本项目 {api: role} 映射。"""
    labels_path = shared_dir() / "role_labels.jsonl"
    if not labels_path.exists():
        return {}
    out = {}
    try:
        for line in labels_path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("project") != project:
                continue
            out[rec.get("api", "")] = rec.get("role", "unknown")
    except Exception:
        pass
    return out


def _fill_slot_candidates(project: str, role: str, scored_apis: list[dict],
                          used_apis: set[str], max_candidates: int = 5,
                          role_labels: dict[str, str] | None = None) -> list[dict]:
    """为一个槽位填候选 API（签名规则筛 + role_labels 标签筛）。

    返回候选列表，每条 {api, signature, header, handle_type, confidence}。
    confidence: "signature" = 签名规则命中；"role_label" = LLM 标注命中。
    """
    candidates = []
    # 第一轮：签名规则筛（高精度，低召回；C++ 方法 signature 含 :: 跳过——规则全线失效）
    for api_entry in scored_apis:
        api_name = api_entry.get("api", "")
        if not api_name or api_name in used_apis:
            continue
        sig = api_entry.get("signature", "")
        if "::" in sig:  # C++ 方法（Class::method），签名规则失效，走第二轮 LLM 标签
            continue
        ruled = _sig_rule_role(api_entry)
        if ruled == role:
            candidates.append({
                "api": api_name,
                "signature": api_entry.get("signature", ""),
                "header": api_entry.get("header", ""),
                "handle_type": _extract_handle_type(api_entry),
                "confidence": "signature",
            })
            if len(candidates) >= max_candidates:
                return candidates
    # 第二轮：role_labels 标签筛（LLM 语义标注，补签名规则漏召回的）
    if role_labels:
        for api_entry in scored_apis:
            api_name = api_entry.get("api", "")
            if not api_name or api_name in used_apis:
                continue
            # 跳过已选入的
            if any(c["api"] == api_name for c in candidates):
                continue
            labeled = role_labels.get(api_name)
            if labeled == role:
                candidates.append({
                    "api": api_name,
                    "signature": api_entry.get("signature", ""),
                    "header": api_entry.get("header", ""),
                    "handle_type": _extract_handle_type(api_entry),
                    "confidence": "role_label",
                })
                if len(candidates) >= max_candidates:
                    break
    # 第三轮（混合方案）：不在此处调 LLM。process/destroy/query 由 _llm_fill_top_n
    # 在 _gen_*_plan 开头并发预标 top N 里签名规则没命中的。此处只筛已有 role_labels。
    # 不够 max_candidates 就返回不够（接受 skipped，避免退化全标 all_apis）。
    return candidates


def _extract_handle_type(api_entry: dict) -> str:
    """从签名首参提 handle 类型（focus 规则 1 + 槽位候选元数据用）。"""
    params = api_entry.get("params", [])
    if not params:
        return ""
    first = params[0] if isinstance(params[0], str) else ""
    # 提取类型名（去 const/修饰符，留指针类型）
    import re
    m = re.search(r'(\w+\s*\*+)', first)
    return m.group(1).strip() if m else ""


# ── peer / cross plan 生成（§7.2）──
def _gen_peer_cross_plan(project: str, mode: str, scored_data: dict,
                         skeletons_data: dict, own_shapes: list[tuple],
                         num_drivers: int,
                         role_labels: dict[str, str] | None = None) -> dict:
    """peer/cross 共用逻辑，只差距离区间。"""
    scored_apis = scored_data.get("scored_apis", [])
    scenario = scored_data.get("scenario", "unknown")
    if role_labels is None:
        role_labels = _load_role_labels(project)
    # 混合方案：开头并发预标 scored top N 里签名规则没命中的（process/destroy/query）
    _llm_fill_top_n(project, scored_apis, role_labels)

    # 距离分档
    if mode == "peer":
        d_min, d_max = 2, 2
    else:  # cross
        d_min, d_max = 3, 99

    # 候选骨架：按到本项目形状的距离分档
    candidates = []
    for sk in skeletons_data.get("skeletons", []):
        sk_seq = tuple(sk["sequence"])
        d = _min_distance_to_own(sk_seq, own_shapes)
        if d_min <= d <= d_max:
            candidates.append((sk, d))
    # 按 support_drivers 降序
    candidates.sort(key=lambda x: x[0].get("support_drivers", 0), reverse=True)

    drivers = []
    skipped = []
    used_apis = set()
    for sk, d in candidates:
        if len(drivers) >= num_drivers:
            break
        sk_seq = sk["sequence"]
        slots = []
        slot_mult = sk.get("slot_multiplicity", {})
        all_filled = True
        for idx, role in enumerate(sk_seq):
            fill_count = slot_mult.get(role, [1, 1])
            cands = _fill_slot_candidates(project, role, scored_apis, used_apis,
                                          role_labels=role_labels)
            if not cands:
                # 填不满 → 整条跳过（§7.2: 宁可少生成也不产残缺）
                skipped.append({
                    "skeleton_id": sk["id"],
                    "failed_slot": idx,
                    "failed_role": role,
                    "reason": "no_candidate",
                    "candidates_found": 0,
                })
                all_filled = False
                break
            used_apis.add(cands[0]["api"])
            slots.append({
                "index": idx,
                "role": role,
                "fill_count": fill_count,
                "candidates": cands,
            })
        if not all_filled:
            continue
        drivers.append({
            "id": f"{mode}#{len(drivers)+1}",
            "skeleton_id": sk["id"],
            "skeleton": list(sk_seq),
            "distance_to_own": d,
            "slots": slots,
            "evidence": {
                "why": f"结构距离 {d}；本项目现有 {len(own_shapes)} 条形状",
                "skeleton_support": {
                    "drivers": sk.get("support_drivers", 0),
                    "projects": sk.get("support_projects", []),
                },
                "source_scenario": scenario,
            },
            "source_tier": mode,
            "prerequisite": None,
            "duplicate_of": None,
        })

    return {
        "mode": mode,
        "project": project,
        "vocab_version": PLAN_VERSION,
        "drivers": drivers,
        "skipped": skipped,
    }


# ── focus plan 生成（§7.1）──
def _gen_focus_plan(project: str, scored_data: dict,
                    own_shapes: list[tuple], num_drivers: int,
                    role_labels: dict[str, str] | None = None) -> dict:
    """focus: 本项目真实序列插未调用 API。

    规则 1（插 configure）：本项目未调用的 configure 类 API，handle 类型与序列已有 API 一致
    规则 2（换同角色替代）：同角色 + handle 一致 + 从未调用（如 png_read_row 替换 png_read_png）
    依赖证据：TODO Q9 改加顺序一致率（Phase 6c），目前 prerequisite 标 inferred_by_llm
    """
    scored_apis = scored_data.get("scored_apis", [])
    scenario = scored_data.get("scenario", "unknown")
    if role_labels is None:
        role_labels = _load_role_labels(project)
    # 混合方案：开头并发预标 scored top N 里签名规则没命中的（process/destroy/query）
    _llm_fill_top_n(project, scored_apis, role_labels)

    if not own_shapes:
        # 本项目无 driver → focus 不可用（§2.4 S_P 为空）
        return {**empty_plan(project, "focus"),
                "skipped": [{"reason": "no_own_drivers", "skeleton_id": "",
                             "failed_slot": 0, "failed_role": "", "candidates_found": 0}]}

    # 取本项目最常见形状作为 base
    from collections import Counter
    shape_counts = Counter(own_shapes)
    base_shape = shape_counts.most_common(1)[0][0]

    # 找未调用的 configure API（规则 1）——签名规则 + role_labels 标签
    tested_apis = {a["api"] for a in scored_apis if a.get("already_fuzzed")}
    untested_configure = [a for a in scored_apis
                          if a.get("untested") and
                          (_sig_rule_role(a) == "configure"
                           or role_labels.get(a.get("api", "")) == "configure")]

    drivers = []
    used = set()
    # 按 handle 类型分组（§7.1: N 个 driver 全动同一个 handle 等于只挖一条路径）
    by_handle = defaultdict(list)
    for a in untested_configure:
        h = _extract_handle_type(a)
        by_handle[h].append(a)

    for handle, apis in by_handle.items():
        if len(drivers) >= num_drivers:
            break
        if not apis:
            continue
        api = apis[0]
        if api["api"] in used:
            continue
        used.add(api["api"])

        # 在 base_shape 的 configure 槽后插入这个 API
        slots = []
        for idx, role in enumerate(base_shape):
            cands = []
            if role == "configure" and idx == 1:  # 第一个 configure 槽插入新 API
                cands = [{
                    "api": api["api"],
                    "signature": api.get("signature", ""),
                    "header": api.get("header", ""),
                    "handle_type": handle,
                    "confidence": "signature",
                }]
            if not cands:
                # 用本项目已测 API 作占位（focus 的 base 序列本就是已验证的）
                tested_for_role = [a for a in scored_apis
                                   if a.get("already_fuzzed") and
                                   (_sig_rule_role(a) == role
                                    or role_labels.get(a.get("api", "")) == role)]
                if tested_for_role:
                    ta = tested_for_role[0]
                    cands = [{
                        "api": ta["api"],
                        "signature": ta.get("signature", ""),
                        "header": ta.get("header", ""),
                        "handle_type": _extract_handle_type(ta),
                        "confidence": "signature",
                    }]
            slots.append({
                "index": idx,
                "role": role,
                "fill_count": [1, 1],
                "candidates": cands,
            })

        drivers.append({
            "id": f"focus#{len(drivers)+1}",
            "skeleton_id": "focus_own",
            "skeleton": list(base_shape),
            "distance_to_own": 0,
            "slots": slots,
            "evidence": {
                "why": f"focus 规则 1：本项目最常见形状插入未调用 configure API {api['api']}",
                "skeleton_support": {"drivers": shape_counts[base_shape], "projects": [project]},
                "source_scenario": scenario,
            },
            "source_tier": "focus",
            "prerequisite": "inferred_by_llm",  # TODO Phase 6c: Q9 顺序证据
            "duplicate_of": None,
        })

    return {
        "mode": "focus",
        "project": project,
        "vocab_version": PLAN_VERSION,
        "drivers": drivers,
        "skipped": [] if drivers else [{"reason": "no_untested_configure",
                                          "skeleton_id": "", "failed_slot": 0,
                                          "failed_role": "configure", "candidates_found": 0}],
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 tools/plan_gen.py <project> [--num-drivers=N]")
        sys.exit(1)
    project = sys.argv[1]
    num_drivers = 5
    for a in sys.argv[2:]:
        if a.startswith("--num-drivers="):
            num_drivers = int(a.split("=", 1)[1])

    # 加载骨架池
    skeletons_data = load_skeletons()
    print(f"[plan_gen] 骨架池: {len(skeletons_data['skeletons'])} 条")

    # 加载本项目 scored.json
    scored_path = intermediate_for(project) / "scored.json"
    if not scored_path.is_file():
        sys.exit(f"[plan_gen] {scored_path} 不存在，请先跑 step1")
    scored_data = json.loads(scored_path.read_text(encoding="utf-8"))
    print(f"[plan_gen] {project}: {len(scored_data.get('scored_apis', []))} API")

    # 本项目现有骨架形状
    own_shapes = _project_own_shapes(project)
    print(f"[plan_gen] 本项目 {len(own_shapes)} 条现有形状")

    # 三模式 plan（共享 role_labels dict，按需标时三模式都更新）
    role_labels = _load_role_labels(project)
    for mode in MODES:
        if mode == "focus":
            plan = _gen_focus_plan(project, scored_data, own_shapes, num_drivers,
                                   role_labels=role_labels)
        else:
            plan = _gen_peer_cross_plan(project, mode, scored_data,
                                         skeletons_data, own_shapes, num_drivers,
                                         role_labels=role_labels)
        p = save_plan(project, mode, plan)
        n_drv = len(plan["drivers"])
        n_skip = len(plan["skipped"])
        print(f"[plan_gen] {mode}: {n_drv} driver, {n_skip} skipped → {p}")

    # 去重检查（§4.3: 标记 duplicate_of 不删除）
    _dedup_check(project)


def _dedup_check(project: str):
    """三份 plan 生成后做骨架级去重检查，标记 duplicate_of（不删除，§4.3）。"""
    plans = {}
    for mode in MODES:
        from plan_loader import load_plan
        try:
            plans[mode] = load_plan(project, mode)
        except Exception:
            return
    # 按 (skeleton_id, slot roles) 找重复
    seen: dict[tuple, str] = {}  # (skel_id, tuple(roles)) → first mode
    for mode, plan in plans.items():
        for drv in plan.get("drivers", []):
            key = (drv.get("skeleton_id"), tuple(drv.get("skeleton", [])))
            if key in seen:
                drv["duplicate_of"] = f"{seen[key]}#{drv['id'].split('#')[-1]}"
            else:
                seen[key] = drv["id"]
                drv["duplicate_of"] = None
        save_plan(project, mode, plan)


if __name__ == "__main__":
    main()
