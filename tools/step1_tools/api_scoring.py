#!/usr/bin/env python3
"""Step1 Section D：API 分类 & 打分 → scored.json。"""
# 从 step1_prepare.py 阶段2 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
from config import intermediate_for

# 打分权重（归一化加权和，两分量均 ∈[0,1]，权重和=1，可调；详见 docs/scoring.md）
# w1 主导：未测 API 优先；w2：富化完整度（tiebreaker，签名>参数>描述）
W_UNTESTED, W_INFO = 0.85, 0.15

# ══════════════════════════════════════════════════════════════════════
# Section D: API 分类 & 打分
# ══════════════════════════════════════════════════════════════════════

def run_api_scoring(project, setup_data):
    """Step D: API 分类 & 打分 → scored.json"""
    print("\n--- API 打分 ---")

    untested_set = set(setup_data.get("untested_apis", []))
    tested_map = {t["name"]: t.get("drivers", []) for t in setup_data.get("tested_apis", [])}

    # api_enrich 富化元数据（signature/params/... 来自 Q6 的 all_apis）
    meta_map = {e["name"]: e for e in setup_data.get("all_apis", []) if e.get("name")}

    scored = []
    for entry in setup_data.get("all_apis", []):
        name = entry["name"]
        if not name:
            continue
        is_untested = name in untested_set
        is_tested = name in tested_map

        meta = meta_map.get(name, {})
        signature = meta.get("signature", "")
        params = meta.get("params", []) or []
        description = meta.get("description", "")
        has_info = bool(signature)

        # 归一化分量（均 ∈ [0,1]），加权求和；权重 W_UNTESTED/W_INFO 见模块顶
        untested_norm = 1.0 if is_untested else 0.0
        info_norm = min(
            (4 if signature else 0) + (3 if params else 0) + (2 if description else 0),
            9,
        ) / 9
        total = W_UNTESTED * untested_norm + W_INFO * info_norm
        scored.append({
            "api": name,
            "already_fuzzed": is_tested, "untested": is_untested,
            "untested_norm": untested_norm,
            "info_norm": info_norm,
            "total_score": round(total, 4),
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
