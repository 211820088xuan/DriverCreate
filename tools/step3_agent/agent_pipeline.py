"""
driver_create/agent_pipeline.py — 多 Agent 编译修复循环的编排器

主循环：
    inject → for round in max_rounds: build → diff → triage → 分发修复 → restage → summary

设计要点：
  - REPAIR_ORDER = ["build", "code"]：同一轮内先编译修复、再代码修复（顺序可配置）。
  - REPAIR_AGENTS = {"build": ..., "code": ...}：错误类型 → 修复 agent 的注册表。
    加新 kind 只需在分诊判据多产一类 + 表里多注册一个 node，不改编排循环。
  - 节点接口统一为 (project, routes_of_this_kind, ctx) -> None。
  - kill switch：DC_DISABLE_AGENT_REPAIR=1 → 只做注入 + 构建，不进分诊/修复循环。
  - 依赖注入：inject_fn/build_fn/diff_fn/triage_fn/restage_fn/dispatch 均可替换，
    便于离线单测（stub 掉 Docker/LLM）。
  - 无 DeepSeek 凭证时优雅降级：triage/修复节点自动 no-op，仍写出 summary。

Route schema（分诊 agent 产出）：
    {"target": <stem>, "kind": "code"|"build", "evidence": [str], "reason": str}
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Optional

from config import intermediate_for
from tools.step3_agent import agent_common as ac
from tools.step3_agent import agent_main


# ══════════════════════════════════════════════════════════════════════
# 扩展点：修复顺序 + agent 注册表（§12.1 / §12.3）
# ══════════════════════════════════════════════════════════════════════

# 同一轮内的分发顺序：先 build 后 code（§2.2 说明：链接/include 错误会掩盖代码错误，
# 先让它能链过，下一轮 code 错误才浮出来）。要调顺序或插新阶段，改这个列表即可。
REPAIR_ORDER: list[str] = ["build", "code"]


# ──────────────────────────────────────────────────────────────────────
# 修复节点（统一接口 (project, routes, ctx) -> None；自守卫 + 优雅降级）
# ──────────────────────────────────────────────────────────────────────

def _driver_source_for(project: str, target: str,
                       mode: Optional[str] = None) -> Optional[Path]:
    """target（stem）→ output/<project>/[<mode>/]<target>.<ext> 的实际源路径（按后缀探测）。"""
    from config import output_for
    base = output_for(project, mode)
    if not base.is_dir():
        return None
    for ext in agent_main.DRIVER_SOURCE_EXTS:
        cand = base / f"{target}{ext}"
        if cand.exists():
            return cand
    return None


def _code_repair_node(project: str, routes: list[dict], ctx: dict) -> None:
    """代码修复节点：改 output/<project>/[<mode>/] 下 driver 源码。

    对每个 route 调 agent_repair.agent_repair_driver，replay_fn 指向
    agent_main.replay_via_get_oss_fuzzer（restage → get_oss_fuzzer.sh → 看产物）。
    mode 从 ctx 取，透传给 _driver_source_for 与 replay_fn（用 partial 绑定）。
    无凭证 / 模块不可用 → 优雅跳过；单个 driver 异常隔离，不拖垮其它。
    """
    if not routes:
        return
    if not ac.deepseek_available():
        print(f"    [code] 无 DeepSeek 凭证，跳过 {len(routes)} 个代码修复（降级）")
        return
    try:
        from tools.step3_agent.agent_repair import agent_repair_driver
    except ImportError:
        print("    [code] agent_repair 模块不可用，跳过")
        return

    from functools import partial
    mode = ctx.get("mode")
    replay_fn = partial(agent_main.replay_via_get_oss_fuzzer, mode=mode)

    fixed = 0
    for r in routes:
        target = r.get("target")
        src = _driver_source_for(project, target, mode) if target else None
        if src is None:
            print(f"    [code] {target}: 找不到源文件，跳过")
            continue
        errors = list(r.get("evidence") or [])
        try:
            result = agent_repair_driver(
                source_path=src,
                binary_name=target,
                base=target,
                errors=errors,
                project=project,
                unavailable_symbols=set(),
                replay_fn=replay_fn,
                output_mirror_paths=[],   # 源码就在 output/<p>/<mode>/，无需镜像
            )
        except Exception as e:   # 单 driver 异常隔离
            print(f"    [code] {target}: 修复异常（隔离）: {e}")
            continue
        if result:
            fixed += 1
            print(f"    [code] {target}: 修复已写回源文件")
        else:
            print(f"    [code] {target}: 未能修复（保留原样）")
    print(f"    [code] 代码修复完成: {fixed}/{len(routes)}")


def _build_fix_node(project: str, routes: list[dict], ctx: dict) -> None:
    """编译修复节点：改 build.sh / Dockerfile 的 dc-injected 标记块。

    调 agent_build_fix.agent_build_fix(project, routes, ctx)。mode 从 ctx 取透传。
    无凭证 / 模块不可用 → 优雅跳过。
    """
    if not routes:
        return
    if not ac.deepseek_available():
        print(f"    [build] 无 DeepSeek 凭证，跳过 {len(routes)} 个编译修复（降级）")
        return
    try:
        from tools.step3_agent.agent_build_fix import agent_build_fix
    except ImportError:
        print("    [build] agent_build_fix 模块不可用，跳过（降级）")
        return
    try:
        ok = agent_build_fix(project, routes, ctx)
        print(f"    [build] 编译修复{'已提交' if ok else '未提交'}"
              f"（{len(routes)} 个目标）")
    except Exception as e:
        print(f"    [build] 编译修复异常（隔离）: {e}")


# 注册表：kind → 修复节点。加新 kind（如 "link"/"header"）在此多注册一项即可。
REPAIR_AGENTS: dict[str, Callable[[str, list[dict], dict], None]] = {
    "build": _build_fix_node,
    "code": _code_repair_node,
}


# ══════════════════════════════════════════════════════════════════════
# 分诊包装器
# ══════════════════════════════════════════════════════════════════════

def _default_triage(project: str, log_path: Path, failed: set[str],
                    mode: Optional[str] = None) -> list[dict]:
    """分诊入口。调用 agent_triage.agent_triage(project, log_path, failed, mode)。

    max_steps 根据失败数量动态调整：
      - 基础值 30（适合 ~20 个 target）
      - 大规模失败时按 len(failed) * 1.5 计算，上限 100

    mode 透传给 agent_triage（分诊时按 mode 过滤失败 target，避免跨 mode 误判）。
    无凭证或模块不可用 → 返回 []（编排器据此停止修复循环，不崩）。
    分诊结果同时存档到 intermediate/<project>/triage[_<mode>].json，空结果也落盘便于排查。
    """
    routes: list[dict] = []
    if ac.deepseek_available():
        try:
            from tools.step3_agent.agent_triage import agent_triage
            # 动态调整 max_steps：基础 30，大规模失败时按 1.5 倍计算，上限 100
            adaptive_steps = min(max(30, int(len(failed) * 1.5)), 100)
            routes = agent_triage(project, str(log_path), sorted(failed),
                                  max_steps=adaptive_steps, mode=mode)
        except ImportError:
            print("  [triage] agent_triage 模块不可用（降级：无法分诊）")
        except Exception as e:
            print(f"  [triage] 分诊异常（降级）: {e}")
    else:
        print("  [triage] 无 DeepSeek 凭证，跳过分诊（降级）")

    triage_file = f"triage_{mode}.json" if mode else "triage.json"
    try:
        (intermediate_for(project) / triage_file).write_text(
            json.dumps(routes, indent=2, ensure_ascii=False)
        )
    except OSError:
        pass
    return routes


# ══════════════════════════════════════════════════════════════════════
# 编排主循环（依赖注入，便于离线单测）
# ══════════════════════════════════════════════════════════════════════

def run_repair_pipeline(
    project: str,
    max_rounds: int = 3,
    *,
    mode: Optional[str] = None,
    inject_fn: Optional[Callable] = None,
    build_fn: Optional[Callable] = None,
    diff_fn: Optional[Callable] = None,
    triage_fn: Optional[Callable] = None,
    restage_fn: Optional[Callable] = None,
    dispatch: Optional[dict[str, Callable[[str, list[dict], dict], None]]] = None,
    disable_repair: Optional[bool] = None,
) -> dict:
    """执行 §2.2 主循环，返回并落盘 agent_build_summary[_<mode>].json 的内容 dict。

    mode=None → legacy 扁平布局；mode='x' → 三模式之一，全程 mode 隔离。

    依赖注入 + mode 绑定：默认 fn 用 functools.partial 绑定 mode（fn 签名保持 (project) 不变，
    便于离线单测注入 stub）；调用方传自定义 fn 时自行负责 mode 处理。
    get_oss_fuzzer.sh 本身 mode-agnostic（提取到扁平 oss-bin/<p>/），故 build_fn 不绑 mode，
    mode 隔离靠 actual_binaries 的名字过滤 + 文件名 _<mode>_crfuzzer 实现。
    """
    from functools import partial
    _bind = lambda fn: partial(fn, mode=mode) if (mode and fn) else fn

    inject_fn = inject_fn or _bind(agent_main.agent_main_inject)
    build_fn = build_fn or agent_main.agent_main_build   # get_oss_fuzzer.sh mode-agnostic
    diff_fn = diff_fn or _bind(agent_main.diff_products)
    triage_fn = triage_fn or _bind(_default_triage)
    restage_fn = restage_fn or _bind(agent_main.restage_drivers)
    dispatch = dispatch if dispatch is not None else REPAIR_AGENTS
    if disable_repair is None:
        disable_repair = os.environ.get("DC_DISABLE_AGENT_REPAIR") == "1"

    mode_tag = f"  mode={mode}" if mode else ""
    print(f"\n{'=' * 60}\n[pipeline] {project}  max_rounds={max_rounds}"
          f"  repair={'off' if disable_repair else 'on'}{mode_tag}\n{'=' * 60}")

    # ── 确保源码存在（不存在则自动从 project.yaml 克隆）──
    if not agent_main.ensure_source_code(project):
        print(f"[pipeline] ⚠️ source_code/{project} 不存在且自动克隆失败")
        print(f"           部分项目的源码在容器构建时才 clone，继续尝试构建...")

    # ── 一次性：主 agent 注入（stage drivers + 改 Dockerfile/build.sh 标记块）──
    injected = False
    try:
        injected = bool(inject_fn(project))
    except Exception as e:
        print(f"[pipeline] 注入异常（继续走构建，可能只编到项目自带 harness）: {e}")
    print(f"[pipeline] 注入完成: {injected}")

    last_kind: dict[str, str] = {}   # target → 最近一次分诊 kind
    rounds_run = 0

    for r in range(max_rounds):
        rounds_run = r + 1
        print(f"\n----- round {rounds_run}/{max_rounds} -----")

        log = build_fn(project, mode=mode)
        built, failed = diff_fn(project)
        print(f"  [diff] built={len(built)} failed={len(failed)}"
              + (f"  失败: {sorted(failed)}" if failed else ""))

        # P1 #4：读 DC_OFFICIAL_RC，官方构建失败 → 项目环境问题，driver 全缺库，
        # 修复循环空耗；round 1 后若仍全失败且官方 RC!=0，跳过剩余轮次。
        from tools.step3_agent.agent_main import read_dc_official_rc, global_build_count
        official_rc = read_dc_official_rc(Path(log))
        if failed and official_rc != 0 and r >= 1:
            print(f"  [pipeline] ⚠️ 官方构建失败（DC_OFFICIAL_RC={official_rc}），"
                  f"driver 缺库根因在项目环境而非 driver 代码，跳过剩余修复轮次")
            break

        # P2 #10：全局 Docker 构建次数上限，防止 N × 3 × 3 = 90 次空转
        from config import DC_GLOBAL_BUILD_BUDGET
        if global_build_count() >= DC_GLOBAL_BUILD_BUDGET:
            print(f"  [pipeline] ⚠️ 全局构建次数达上限（{DC_GLOBAL_BUILD_BUDGET}），"
                  f"跳过剩余修复轮次")
            break

        if not failed:
            print("  [pipeline] 全部编译通过，结束循环")
            break

        if disable_repair:
            print("  [pipeline] DC_DISABLE_AGENT_REPAIR=1，只注入+构建，不进修复循环")
            break

        # ── 分诊 ──
        routes = triage_fn(project, log, failed) or []
        if not routes:
            print("  [pipeline] 无分诊结果（无凭证或分诊失败），停止修复循环")
            break

        # ── 分发：REPAIR_ORDER 固定「先 build 后 code」──
        for kind in REPAIR_ORDER:
            kroutes = [rt for rt in routes if rt.get("kind") == kind]
            for rt in kroutes:
                tgt = rt.get("target")
                if tgt:
                    last_kind[tgt] = kind
            if not kroutes:
                continue
            node = dispatch.get(kind)
            if node is None:
                print(f"  [pipeline] kind='{kind}' 无注册修复 agent，跳过 {len(kroutes)} 个")
                continue
            ctx = {"log_path": log, "round": rounds_run,
                   "max_rounds": max_rounds, "mode": mode}
            try:
                node(project, kroutes, ctx)
            except Exception as e:   # 单个修复 agent 异常不拖垮循环（§9.4）
                print(f"  [pipeline] kind='{kind}' 修复节点异常（隔离）: {e}")

        # ── 若改了 driver 源码，需重新 stage 供下一轮构建（§2.2）──
        try:
            restage_fn(project)
        except Exception as e:
            print(f"  [pipeline] restage 异常: {e}")

    # ── 汇总（§5 schema）──
    summary = _build_summary(project, rounds_run, last_kind, diff_fn, mode)
    out_name = f"agent_build_summary_{mode}.json" if mode else "agent_build_summary.json"
    out_path = intermediate_for(project) / out_name
    try:
        out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
        print(f"\n[pipeline] summary → {out_path}")
    except OSError as e:
        print(f"[pipeline] summary 落盘失败: {e}")
    print(f"[pipeline] {project}: {summary['success']}/{summary['total']} 编译成功"
          f"（{rounds_run} 轮）")
    return summary


def _build_summary(project: str, rounds_run: int, last_kind: dict[str, str],
                   diff_fn: Callable, mode: Optional[str] = None) -> dict:
    """按 §5 schema 构造 summary。target 全集 = 期望产物；status 以最终 diff 为准。"""
    built, failed = diff_fn(project)
    all_targets = sorted(built | failed)
    per_target = [
        {
            "target": t,
            "status": "ok" if t in built else "failed",
            "last_kind": last_kind.get(t),
        }
        for t in all_targets
    ]
    return {
        "project": project,
        "mode": mode or "legacy",
        "rounds": rounds_run,
        "total": len(all_targets),
        "success": len(built),
        "per_target": per_target,
        "binaries": sorted(built),
    }


# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════

def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: python3 -m tools.step3_agent.agent_pipeline <project> [--max-rounds=N] "
              "[--mode=focus|peer|cross]")
        sys.exit(1)
    project = args[0]
    max_rounds = 3
    mode = None
    for a in args[1:]:
        if a.startswith("--max-rounds="):
            max_rounds = int(a.split("=", 1)[1])
        elif a.startswith("--mode="):
            mode = a.split("=", 1)[1]
    run_repair_pipeline(project, max_rounds=max_rounds, mode=mode)


if __name__ == "__main__":
    main()
