#!/usr/bin/env python3
"""
contracts/plans.py — plan_<mode>.json 的读写接口 + schema 校验

数据契约（重构指导 §4.3）：
  {
    "mode": "peer",
    "project": "libpng",
    "vocab_version": "v4",
    "drivers": [
      {
        "id": "peer#1",
        "skeleton_id": "sk_0007",
        "skeleton": ["create","configure","data_sink","process","destroy"],
        "distance_to_own": 2,
        "slots": [
          {
            "index": 0,
            "role": "create",
            "fill_count": [1, 1],
            "candidates": [
              {"api":"png_create_read_struct","signature":"...","header":"png.h",
               "handle_type":"png_structp","confidence":"llm"}
            ]
          }
        ],
        "evidence": {
          "why":"...","skeleton_support":{"drivers":18,"projects":[...]},
          "source_scenario":"CompressionArchive"
        },
        "source_tier": "peer",
        "prerequisite": null,
        "duplicate_of": null
      }
    ],
    "skipped": [
      {"skeleton_id":"sk_0012","failed_slot":2,"failed_role":"process",
       "reason":"no_candidate","candidates_found":0}
    ]
  }

供 step2（Phase 8 改造后读 plan 填槽）与 plan_gen（Phase 6）共用。
夹具：contracts.plans.SAMPLE_PLAN 是手写的合法 plan，供 step2 无真实 plan 时先跑通。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

# 直接执行时把根目录加进 sys.path（与 tools/ 脚本同机制），包形式 import 无需此行
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import plan_path, MODES, PLAN_VERSION, ROLES

# query / unknown 不进骨架序列（§2.1），但可作 confidence 标签出现
EXTENDED_LABELS = ROLES + ("query", "unknown")


class PlanError(Exception):
    """plan 文件结构错误（加载/校验失败）"""


# ──────────────────────────────────────────────────────────────────────
# 加载 / 保存
# ──────────────────────────────────────────────────────────────────────

def load_plan(project: str, mode: str) -> dict:
    """加载 intermediate/<project>/plan_<mode>.json。文件不存在 → PlanError。

    返回原始 dict（已通过 validate_plan 校验）。
    """
    if mode not in MODES:
        raise PlanError(f"非法 mode {mode!r}，可选: {MODES}")
    p = plan_path(project, mode)
    if not p.is_file():
        raise PlanError(f"plan 文件不存在: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        raise PlanError(f"plan 解析失败 {p}: {e}") from e
    issues = validate_plan(data, mode)
    if issues:
        raise PlanError(f"plan schema 校验失败 {p}:\n  - " + "\n  - ".join(issues))
    return data


def save_plan(project: str, mode: str, plan: dict) -> Path:
    """落盘 plan_<mode>.json。落盘前校验，不合法 → PlanError。返回路径。"""
    issues = validate_plan(plan, mode)
    if issues:
        raise PlanError(f"拒绝写入不合法 plan:\n  - " + "\n  - ".join(issues))
    p = plan_path(project, mode)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    return p


def empty_plan(project: str, mode: str) -> dict:
    """造一个空 plan（0 driver, 0 skipped）的骨架。plan_gen 写盘前可作起点。"""
    if mode not in MODES:
        raise PlanError(f"非法 mode {mode!r}")
    return {
        "mode": mode,
        "project": project,
        "vocab_version": PLAN_VERSION,
        "drivers": [],
        "skipped": [],
    }


# ──────────────────────────────────────────────────────────────────────
# schema 校验（轻量结构检查，不验语义）
# ──────────────────────────────────────────────────────────────────────

def validate_plan(plan: dict, mode: Optional[str] = None) -> list[str]:
    """校验 plan dict 是否符合 §4.3 schema。

    返回 issue 列表（空 = 合法）。只做结构 / 类型 / 枚举检查，不验语义
    （如 skeleton 是否在骨架池存在、candidates 是否真实 API 等——那是 plan_gen 的职责）。
    """
    issues: list[str] = []

    if not isinstance(plan, dict):
        return ["plan 顶层必须是 dict"]

    # 顶层字段
    for k in ("mode", "project", "vocab_version", "drivers", "skipped"):
        if k not in plan:
            issues.append(f"缺顶层字段 {k!r}")

    if "mode" in plan and plan["mode"] != mode:
        issues.append(f"mode 字段 {plan['mode']!r} 与传入 mode {mode!r} 不一致")

    if "vocab_version" in plan and plan["vocab_version"] != PLAN_VERSION:
        issues.append(f"vocab_version 应为 {PLAN_VERSION!r}，实为 {plan['vocab_version']!r}")

    if "drivers" in plan and not isinstance(plan["drivers"], list):
        issues.append("drivers 必须是 list")
    if "skipped" in plan and not isinstance(plan["skipped"], list):
        issues.append("skipped 必须是 list")

    # drivers 每项
    for i, d in enumerate(plan.get("drivers", []) or []):
        if not isinstance(d, dict):
            issues.append(f"drivers[{i}] 必须是 dict")
            continue
        prefix = f"drivers[{i}]"
        for k in ("id", "skeleton_id", "skeleton", "slots", "source_tier"):
            if k not in d:
                issues.append(f"{prefix} 缺字段 {k!r}")

        skel = d.get("skeleton")
        if isinstance(skel, list):
            for j, r in enumerate(skel):
                if r not in ROLES:
                    issues.append(f"{prefix}.skeleton[{j}]={r!r} 不在 {ROLES}")
        elif skel is not None:
            issues.append(f"{prefix}.skeleton 必须是 list")

        if "slots" in plan and not isinstance(d.get("slots"), list):
            issues.append(f"{prefix}.slots 必须是 list")

        for j, s in enumerate(d.get("slots") or []):
            if not isinstance(s, dict):
                issues.append(f"{prefix}.slots[{j}] 必须是 dict")
                continue
            sp = f"{prefix}.slots[{j}]"
            for k in ("index", "role", "fill_count", "candidates"):
                if k not in s:
                    issues.append(f"{sp} 缺字段 {k!r}")
            if s.get("role") not in ROLES and s.get("role") is not None:
                issues.append(f"{sp}.role={s.get('role')!r} 不在 {ROLES}")
            fc = s.get("fill_count")
            if fc is not None and (not isinstance(fc, list) or len(fc) != 2):
                issues.append(f"{sp}.fill_count 应为 [min,max] 二元组")
            if not isinstance(s.get("candidates"), list):
                issues.append(f"{sp}.candidates 必须是 list")

        # source_tier 枚举
        st = d.get("source_tier")
        if st is not None and st not in MODES:
            issues.append(f"{prefix}.source_tier={st!r} 不在 {MODES}")

    # skipped 每项
    for i, s in enumerate(plan.get("skipped") or []):
        if not isinstance(s, dict):
            issues.append(f"skipped[{i}] 必须是 dict")
            continue
        for k in ("skeleton_id", "failed_slot", "failed_role", "reason"):
            if k not in s:
                issues.append(f"skipped[{i}] 缺字段 {k!r}")

    return issues


# ──────────────────────────────────────────────────────────────────────
# 便捷查询（step2 / plan_gen 用）
# ──────────────────────────────────────────────────────────────────────

def iter_slots(plan: dict):
    """迭代 (driver, slot) 对。yield (driver_dict, slot_dict)。"""
    for d in plan.get("drivers", []) or []:
        for s in d.get("slots", []) or []:
            yield d, s


def driver_by_id(plan: dict, driver_id: str) -> Optional[dict]:
    """按 id 查 driver。"""
    for d in plan.get("drivers", []) or []:
        if d.get("id") == driver_id:
            return d
    return None


def count_skipped(plan: dict) -> dict[str, int]:
    """skipped 按 reason 分组计数（诊断用：看是 no_candidate 多还是别的）。"""
    from collections import Counter
    return dict(Counter(s.get("reason", "?") for s in plan.get("skipped") or []))


# ──────────────────────────────────────────────────────────────────────
# 手写样例夹具（§5.4：让 step2 改造可在无真实 plan 时先跑通）
# ──────────────────────────────────────────────────────────────────────

SAMPLE_PLAN = {
    "mode": "peer",
    "project": "c-blosc2",
    "vocab_version": "v4",
    "drivers": [
        {
            "id": "peer#1",
            "skeleton_id": "sk_0001",
            "skeleton": ["create", "configure", "data_sink", "process", "destroy"],
            "distance_to_own": 2,
            "slots": [
                {
                    "index": 0,
                    "role": "create",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_schunk_new",
                            "signature": "blosc2_schunk* blosc2_schunk_new(blosc2_dparams* dparams)",
                            "header": "blosc2.h",
                            "handle_type": "blosc2_schunk*",
                            "confidence": "llm",
                        }
                    ],
                },
                {
                    "index": 1,
                    "role": "configure",
                    "fill_count": [1, 2],
                    "candidates": [
                        {
                            "api": "blosc2_cbuffer_sizes",
                            "signature": "void blosc2_cbuffer_sizes(const void* cbuffer, int* nbytes, int* cbytes, int* blocksize)",
                            "header": "blosc2.h",
                            "handle_type": "void*",
                            "confidence": "signature",
                        }
                    ],
                },
                {
                    "index": 2,
                    "role": "data_sink",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_decompress_ctx",
                            "signature": "int blosc2_decompress_ctx(blosc2_context* ctx, const void* src, int32_t srcsize, void* dest, int32_t destsize)",
                            "header": "blosc2.h",
                            "handle_type": "blosc2_context*",
                            "confidence": "llm",
                        }
                    ],
                },
                {
                    "index": 3,
                    "role": "process",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_decompress",
                            "signature": "int blosc2_decompress(const void* src, int32_t srcsize, void* dest, int32_t destsize)",
                            "header": "blosc2.h",
                            "handle_type": "void*",
                            "confidence": "llm",
                        }
                    ],
                },
                {
                    "index": 4,
                    "role": "destroy",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_schunk_free",
                            "signature": "int blosc2_schunk_free(blosc2_schunk* schunk)",
                            "header": "blosc2.h",
                            "handle_type": "blosc2_schunk*",
                            "confidence": "llm",
                        }
                    ],
                },
            ],
            "evidence": {
                "why": "结构距离 2；本项目现有 3 条形状均无 data_sink+configure 组合",
                "skeleton_support": {"drivers": 18, "projects": ["libarchive", "zstd"]},
                "source_scenario": "CompressionArchive",
            },
            "source_tier": "peer",
            "prerequisite": None,
            "duplicate_of": None,
        },
        {
            "id": "peer#2",
            "skeleton_id": "sk_0007",
            "skeleton": ["create", "data_sink", "process", "destroy"],
            "distance_to_own": 3,
            "slots": [
                {
                    "index": 0,
                    "role": "create",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_cbuffer_sizes",
                            "signature": "void blosc2_cbuffer_sizes(const void* cbuffer, int* nbytes, int* cbytes, int* blocksize)",
                            "header": "blosc2.h",
                            "handle_type": "void*",
                            "confidence": "signature",
                        }
                    ],
                },
                {
                    "index": 1,
                    "role": "data_sink",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_decompress",
                            "signature": "int blosc2_decompress(const void* src, int32_t srcsize, void* dest, int32_t destsize)",
                            "header": "blosc2.h",
                            "handle_type": "void*",
                            "confidence": "llm",
                        }
                    ],
                },
                {
                    "index": 2,
                    "role": "process",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_compress_ctx",
                            "signature": "int blosc2_compress_ctx(blosc2_context* ctx, const void* src, int32_t srcsize, void* dest, int32_t destsize)",
                            "header": "blosc2.h",
                            "handle_type": "blosc2_context*",
                            "confidence": "llm",
                        }
                    ],
                },
                {
                    "index": 3,
                    "role": "destroy",
                    "fill_count": [1, 1],
                    "candidates": [
                        {
                            "api": "blosc2_free",
                            "signature": "void blosc2_free(void* ptr)",
                            "header": "blosc2.h",
                            "handle_type": "void*",
                            "confidence": "signature",
                        }
                    ],
                },
            ],
            "evidence": {
                "why": "结构距离 3；缺 configure 槽的最简骨架，cross-structure 验证用",
                "skeleton_support": {"drivers": 12, "projects": ["zstd"]},
                "source_scenario": "CompressionArchive",
            },
            "source_tier": "peer",
            "prerequisite": None,
            "duplicate_of": None,
        },
    ],
    "skipped": [
        {
            "skeleton_id": "sk_0012",
            "failed_slot": 2,
            "failed_role": "process",
            "reason": "no_candidate",
            "candidates_found": 0,
        }
    ],
}


def write_sample_fixture(project: str = "c-blosc2", mode: str = "peer") -> Path:
    """把 SAMPLE_PLAN 落盘为 intermediate/<project>/plan_<mode>.json（夹具）。

    用于 step2 改造时在没有真实 plan_gen 产出的情况下先跑通。
    调试用：python3 -c 'import plan_loader as p; p.write_sample_fixture()'
    """
    p = plan_path(project, mode)
    p.parent.mkdir(parents=True, exist_ok=True)
    plan = dict(SAMPLE_PLAN)
    plan["project"] = project
    plan["mode"] = mode
    p.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[plan_loader] 样例夹具已写入 {p}")
    return p


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "fixture":
        proj = sys.argv[2] if len(sys.argv) > 2 else "c-blosc2"
        mode = sys.argv[3] if len(sys.argv) > 3 else "peer"
        write_sample_fixture(proj, mode)
    else:
        # 自测：校验 SAMPLE_PLAN
        issues = validate_plan(SAMPLE_PLAN, "peer")
        if issues:
            print("SAMPLE_PLAN 校验失败:")
            for i in issues:
                print(f"  - {i}")
            sys.exit(1)
        print(f"SAMPLE_PLAN 校验通过（{len(SAMPLE_PLAN['drivers'])} driver, "
              f"{len(SAMPLE_PLAN['skipped'])} skipped）")
        print(f"  用法：python3 plan_loader.py fixture [project] [mode]  # 落盘夹具")
