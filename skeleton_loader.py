#!/usr/bin/env python3
"""
skeleton_loader.py — skeletons.json + scenario/<场景>.json 的读写 + schema 校验

数据契约（重构指导 §4.1 / §4.2）：

【§4.1 skeletons.json】（跨项目共享，全局算一次，落 _shared/skeletons.json）
{
  "vocab_version": "v4",
  "order_field": "order_last",
  "skeletons": [
    {
      "id": "sk_0001",
      "sequence": ["create","configure","data_sink","process","destroy"],
      "support_drivers": 18,
      "support_projects": ["libarchive","c-blosc2"],
      "scenarios": {"CompressionArchive": 18},
      "scenario_confidence": "normal",
      "single_lib_dominated": false,
      "slot_multiplicity": {"configure":[1,4], "process":[1,2]},
      "example_drivers": ["libarchive/fuzz_archive.c"],
      "source_enrichment_rate": 0.98
    }
  ]
}

【§4.2 _shared/scenario/<场景>.json】（每场景一份）
{
  "scenario": "CompressionArchive",
  "usable_drivers": 53,
  "confidence": "normal",
  "single_lib_dominated": false,
  "project_distribution": {"libarchive":25,"zstd":20,"c-blosc2":4},
  "peer_projects_ranked": ["libarchive","zstd","c-blosc2"],
  "skeleton_ids": ["sk_0001","sk_0007"],
  "data_strategy_distribution": {"byte-sliced":20,"direct":18,"tlv":9}
}

字段用途见重构指导 §4.1/§4.2。本模块只做结构校验，不验语义
（如 skeleton 序列是否合法折叠、scenario 引用的 skeleton 是否存在等——那是
skeleton_mine / plan_gen 的职责）。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from config import shared_dir, scenario_dir, PLAN_VERSION, ORDER_FIELD, ROLES

SKELETONS_FILE = "skeletons.json"
CONFIDENCE_TIERS = ("normal", "low-confidence", "not-used")
# data_strategy 枚举（_classify_data_strategy 产出，§4.2 注释）
DATA_STRATEGIES = ("byte-sliced", "direct", "tlv", "producer", "unknown")


class SkeletonError(Exception):
    """skeletons / scenario 文件结构错误"""


# ══════════════════════════════════════════════════════════════════════
# skeletons.json
# ══════════════════════════════════════════════════════════════════════

def skeletons_path() -> Path:
    """_shared/skeletons.json 路径。"""
    return shared_dir() / SKELETONS_FILE


def load_skeletons() -> dict:
    """加载 _shared/skeletons.json。文件不存在 → SkeletonError。返回已校验 dict。"""
    p = skeletons_path()
    if not p.is_file():
        raise SkeletonError(f"skeletons.json 不存在: {p}（请先跑 skeleton_mine）")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise SkeletonError(f"skeletons.json 解析失败: {e}") from e
    issues = validate_skeletons(data)
    if issues:
        raise SkeletonError("skeletons.json 校验失败:\n  - " + "\n  - ".join(issues))
    return data


def save_skeletons(data: dict) -> Path:
    """落盘 skeletons.json。写前校验，不合法 → SkeletonError。"""
    issues = validate_skeletons(data)
    if issues:
        raise SkeletonError("拒绝写入不合法 skeletons:\n  - " + "\n  - ".join(issues))
    p = skeletons_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def empty_skeletons() -> dict:
    """造空骨架池（0 skeleton）。skeleton_mine 写盘前可作起点。"""
    return {
        "vocab_version": PLAN_VERSION,
        "order_field": "order_last",
        "skeletons": [],
    }


def validate_skeletons(data: dict) -> list[str]:
    """校验 skeletons.json 结构。返回 issue 列表（空 = 合法）。"""
    issues: list[str] = []
    if not isinstance(data, dict):
        return ["skeletons 顶层必须是 dict"]
    for k in ("vocab_version", "order_field", "skeletons"):
        if k not in data:
            issues.append(f"缺顶层字段 {k!r}")
    if data.get("vocab_version") != PLAN_VERSION:
        issues.append(f"vocab_version 应为 {PLAN_VERSION!r}，实为 {data.get('vocab_version')!r}")
    if data.get("order_field") not in (None, "order", "order_last"):
        issues.append(f"order_field 应为 'order' 或 'order_last'，实为 {data.get('order_field')!r}")

    skels = data.get("skeletons")
    if not isinstance(skels, list):
        issues.append("skeletons 必须是 list")
        return issues

    seen_ids: set[str] = set()
    for i, sk in enumerate(skels):
        if not isinstance(sk, dict):
            issues.append(f"skeletons[{i}] 必须是 dict")
            continue
        prefix = f"skeletons[{i}]"
        for k in ("id", "sequence", "support_drivers", "support_projects",
                 "scenarios", "scenario_confidence"):
            if k not in sk:
                issues.append(f"{prefix} 缺字段 {k!r}")

        sid = sk.get("id")
        if sid in seen_ids:
            issues.append(f"{prefix} id={sid!r} 重复")
        if sid:
            seen_ids.add(sid)

        seq = sk.get("sequence")
        if isinstance(seq, list):
            for j, r in enumerate(seq):
                if r not in ROLES:
                    issues.append(f"{prefix}.sequence[{j}]={r!r} 不在 {ROLES}")
        elif seq is not None:
            issues.append(f"{prefix}.sequence 必须是 list")

        if sk.get("scenario_confidence") not in CONFIDENCE_TIERS and sk.get("scenario_confidence") is not None:
            issues.append(f"{prefix}.scenario_confidence={sk.get('scenario_confidence')!r} 不在 {CONFIDENCE_TIERS}")

        sm = sk.get("slot_multiplicity")
        if sm is not None and not isinstance(sm, dict):
            issues.append(f"{prefix}.slot_multiplicity 必须是 dict[role->[min,max]]")

    return issues


# ══════════════════════════════════════════════════════════════════════
# scenario/<scenario>.json
# ══════════════════════════════════════════════════════════════════════

def scenario_path(scenario: str) -> Path:
    """_shared/scenario/<scenario>.json 路径。"""
    # 场景名可能含 / 等不安全字符，仅取文件名部分
    safe = "".join(c for c in scenario if c.isalnum() or c in "._-") or "unknown"
    return scenario_dir() / f"{safe}.json"


def load_scenario(scenario: str) -> dict:
    """加载某场景的 JSON。文件不存在 → SkeletonError。"""
    p = scenario_path(scenario)
    if not p.is_file():
        raise SkeletonError(f"scenario JSON 不存在: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise SkeletonError(f"scenario JSON 解析失败: {e}") from e
    issues = validate_scenario(data, scenario)
    if issues:
        raise SkeletonError("scenario JSON 校验失败:\n  - " + "\n  - ".join(issues))
    return data


def save_scenario(scenario: str, data: dict) -> Path:
    """落盘 scenario/<scenario>.json。写前校验。"""
    issues = validate_scenario(data, scenario)
    if issues:
        raise SkeletonError("拒绝写入不合法 scenario:\n  - " + "\n  - ".join(issues))
    p = scenario_path(scenario)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def empty_scenario(scenario: str) -> dict:
    """造空场景（0 skeleton）。"""
    return {
        "scenario": scenario,
        "usable_drivers": 0,
        "confidence": "not-used",
        "single_lib_dominated": False,
        "project_distribution": {},
        "peer_projects_ranked": [],
        "skeleton_ids": [],
        "data_strategy_distribution": {},
    }


def validate_scenario(data: dict, scenario: Optional[str] = None) -> list[str]:
    """校验 scenario JSON 结构。"""
    issues: list[str] = []
    if not isinstance(data, dict):
        return ["scenario 顶层必须是 dict"]
    for k in ("scenario", "usable_drivers", "confidence", "skeleton_ids"):
        if k not in data:
            issues.append(f"缺字段 {k!r}")
    if scenario and data.get("scenario") != scenario:
        issues.append(f"scenario 字段 {data.get('scenario')!r} 与传入 {scenario!r} 不一致")
    conf = data.get("confidence")
    if conf not in CONFIDENCE_TIERS and conf is not None:
        issues.append(f"confidence={conf!r} 不在 {CONFIDENCE_TIERS}")
    if not isinstance(data.get("skeleton_ids", []), list):
        issues.append("skeleton_ids 必须是 list")
    if not isinstance(data.get("peer_projects_ranked", []), list):
        issues.append("peer_projects_ranked 必须是 list")
    dsd = data.get("data_strategy_distribution")
    if dsd is not None and not isinstance(dsd, dict):
        issues.append("data_strategy_distribution 必须是 dict[str->int]")
    return issues


# ══════════════════════════════════════════════════════════════════════
# 便捷查询
# ══════════════════════════════════════════════════════════════════════

def skeleton_by_id(skeletons_data: dict, skel_id: str) -> Optional[dict]:
    """按 id 查 skeleton。"""
    for sk in skeletons_data.get("skeletons", []) or []:
        if sk.get("id") == skel_id:
            return sk
    return None


def top_skeletons(skeletons_data: dict, n: int = 10,
                  by: str = "support_drivers") -> list[dict]:
    """取 support_drivers 降序前 N 条骨架（peer/cross 候选排序用）。"""
    skels = list(skeletons_data.get("skeletons", []) or [])
    skels.sort(key=lambda s: s.get(by, 0), reverse=True)
    return skels[:n]


# ══════════════════════════════════════════════════════════════════════
# 手写样例夹具（skeleton_mine / plan_gen 改造前先跑通用）
# ══════════════════════════════════════════════════════════════════════

SAMPLE_SKELETONS = {
    "vocab_version": "v4",
    "order_field": "order_last",
    "skeletons": [
        {
            "id": "sk_0001",
            "sequence": ["create", "configure", "data_sink", "process", "destroy"],
            "support_drivers": 18,
            "support_projects": ["libarchive", "c-blosc2"],
            "scenarios": {"CompressionArchive": 18},
            "scenario_confidence": "normal",
            "single_lib_dominated": False,
            "slot_multiplicity": {"configure": [1, 4], "process": [1, 2]},
            "example_drivers": ["libarchive/fuzz_archive.c"],
            "source_enrichment_rate": 0.98,
        },
        {
            "id": "sk_0007",
            "sequence": ["create", "data_sink", "process", "destroy"],
            "support_drivers": 12,
            "support_projects": ["zstd"],
            "scenarios": {"CompressionArchive": 12},
            "scenario_confidence": "normal",
            "single_lib_dominated": False,
            "slot_multiplicity": {"process": [1, 1]},
            "example_drivers": ["zstd/zstd_decompress_fuzzer.c"],
            "source_enrichment_rate": 0.95,
        },
        {
            "id": "sk_0012",
            "sequence": ["create", "configure", "process", "destroy"],
            "support_drivers": 8,
            "support_projects": ["mbedtls"],
            "scenarios": {"CryptoSecurity": 8},
            "scenario_confidence": "normal",
            "single_lib_dominated": True,
            "slot_multiplicity": {"configure": [1, 3]},
            "example_drivers": ["mbedtls/ssl_fuzz.c"],
            "source_enrichment_rate": 0.72,
        },
    ],
}

SAMPLE_SCENARIO = {
    "scenario": "CompressionArchive",
    "usable_drivers": 53,
    "confidence": "normal",
    "single_lib_dominated": False,
    "project_distribution": {"libarchive": 25, "zstd": 20, "c-blosc2": 4, "miniz": 2, "lz4": 2},
    "peer_projects_ranked": ["libarchive", "zstd", "c-blosc2"],
    "skeleton_ids": ["sk_0001", "sk_0007"],
    "data_strategy_distribution": {"byte-sliced": 20, "direct": 18, "tlv": 9, "producer": 4, "unknown": 2},
}


def write_sample_skeletons() -> Path:
    """把 SAMPLE_SKELETONS 落盘为 _shared/skeletons.json（夹具）。"""
    return save_skeletons(SAMPLE_SKELETONS)


def write_sample_scenario(scenario: str = "CompressionArchive") -> Path:
    """把 SAMPLE_SCENARIO 落盘为 _shared/scenario/<scenario>.json（夹具）。"""
    data = dict(SAMPLE_SCENARIO)
    data["scenario"] = scenario
    return save_scenario(scenario, data)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "fixture":
        p1 = write_sample_skeletons()
        p2 = write_sample_scenario()
        print(f"[skeleton_loader] 夹具已写入:\n  {p1}\n  {p2}")
    else:
        # 自测：校验样例
        issues1 = validate_skeletons(SAMPLE_SKELETONS)
        issues2 = validate_scenario(SAMPLE_SCENARIO, "CompressionArchive")
        if issues1 or issues2:
            print("SAMPLE 校验失败:")
            for i in issues1 + issues2:
                print(f"  - {i}")
            sys.exit(1)
        print(f"SAMPLE_SKELETONS 校验通过（{len(SAMPLE_SKELETONS['skeletons'])} 条骨架）")
        print(f"SAMPLE_SCENARIO 校验通过（{len(SAMPLE_SCENARIO['skeleton_ids'])} 条 skeleton_id）")
        print(f"  用法：python3 skeleton_loader.py fixture  # 落盘夹具")
