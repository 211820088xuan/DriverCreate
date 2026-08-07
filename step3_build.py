#!/usr/bin/env python3
"""
step3_build.py — Fuzz Driver 流水线**第三阶段：编译验证与修复**

本脚本是 pipeline 第三阶段的统一入口，也是 `run_pipeline.py --build` 调用的对象。

默认（推荐）跑**多 Agent 编译修复循环**（委托 agent.agent_pipeline）：
    注入 → 构建 → 分诊 → 分发修复 → 重构建，循环 ≤ max_rounds，直到全通过或达轮数上限。

两种确定性降级（不进 LLM 修复，供已注入好或无 DeepSeek 凭证时用）：
  --no-repair : restage + 构建 + 产物比对（跑下方构建模型第 2–4 步，不注入不修复）；
  --no-build  : 只比对现有 oss-bin/<project>/ 产物，连构建都跳过。

三模式隔离（focus/peer/cross）：driver 源在 output/<project>/driver/<mode>/*_<mode>_crfuzzer.{ext}，
产物比对看 output/<project>/oss-bin/<mode>/。--mode 指定单模式；不传走 legacy 扁平。

构建模型（与 agent_pipeline 一致，见 spec §3）：
  1. driver 源码在 output/<project>/driver/[<mode>/]；
  2. restage 到 oss-fuzz/projects/<project>/（Docker 构建上下文，manifest-guarded，扁平、mode 在文件名）；
  3. 跑 scripts/get_oss_fuzzer.sh <project> [<dc_only>] [<mode>]（build_image → build_fuzzers → 提取到 output/<project>/oss-bin/[<mode>/]）；
  4. 期望产物（driver stem）对比 output/<project>/oss-bin/[<mode>/] 实际产物，报告成功/失败。

用法:
  python3 step3_build.py <project>                          # 默认：注入 + 构建 + 分诊 + 修复循环
  python3 step3_build.py <project> --max-rounds=N            # 指定修复循环最大轮数（默认 3）
  python3 step3_build.py <project> --mode=focus              # 三模式之一（focus/peer/cross）
  python3 step3_build.py <project> --no-repair               # 确定性：restage + 构建 + 比对，不修复
  python3 step3_build.py <project> --no-build                # 只比对现有 oss-bin/ 产物（不重新构建）

> kill switch：环境变量 DC_DISABLE_AGENT_REPAIR=1 → 默认路径的修复循环只注入+构建，不进 LLM 修复。
"""

import sys
import json

from config import output_for, OSS_FUZZ_DIR, intermediate_for
from agent import agent_main

OSS_FUZZ_PROJECTS = OSS_FUZZ_DIR / "projects"


def run_repair(project: str, max_rounds: int = 3,
               mode: str | None = None) -> dict:
    """默认路径：委托多 Agent 编译修复循环（注入 → 构建 → 分诊 → 修复 → 重构建）。

    mode 透传给 agent_pipeline，使 restage / diff / inject / replay 全程 mode 隔离。
    无 DeepSeek 凭证时 agent_pipeline 自身会优雅降级为「只注入 + 构建」。
    """
    from agent import agent_pipeline
    return agent_pipeline.run_repair_pipeline(project, max_rounds=max_rounds,
                                              mode=mode)


def build_and_report(project: str, do_build: bool = True,
                     mode: str | None = None) -> dict:
    """确定性降级路径：restage →（可选）get_oss_fuzzer.sh → diff → 落盘 step3_summary.json。

    不注入、不进 LLM 修复。供 --no-repair / --no-build 使用。mode 透传给所有 agent_main 调用。
    """
    out_dir = output_for(project, mode)
    if not out_dir.is_dir():
        raise RuntimeError(
            f"[step3] 没找到生成产物目录 {out_dir}，请先跑 step2_generate.py"
            + (f"（mode={mode}）" if mode else ""))

    sources = agent_main.collect_driver_sources(project, mode)
    if not sources:
        raise RuntimeError(f"[step3] {out_dir} 下没有可用的 driver 源文件")
    print(f"[step3] [{mode or 'legacy'}] 收集到 {len(sources)} 个 driver 源文件")

    # 确保 source_code/<project> 存在（不存在则自动从 project.yaml 克隆）
    if not agent_main.ensure_source_code(project):
        print(f"[step3] ⚠️ source_code/{project} 不存在且自动克隆失败，继续尝试构建...")
        print(f"        （部分项目的源码在容器构建时才 clone，本地缺失不一定影响构建）")

    proj_dir = OSS_FUZZ_PROJECTS / project
    if not proj_dir.is_dir():
        raise RuntimeError(
            f"[step3] OSS-Fuzz 项目目录不存在: {proj_dir}\n"
            f"        请确认项目已放入 oss-fuzz/projects/{project}/。"
        )

    # 1. restage（manifest-guarded，首轮 touch-none；mode-specific manifest）
    staged = agent_main.restage_drivers(project, mode)
    print(f"[step3] restage {len(staged)} 个 driver 到 {proj_dir}")

    # 1.5 更新 build.sh + Dockerfile 的 glob 为当前 mode（--no-repair 不调 inject agent，
    # mode 切换时 glob 还是上一模式的，会编错 driver）
    if mode:
        import re
        for fn in ("build.sh", "Dockerfile"):
            fp = proj_dir / fn
            if not fp.exists():
                continue
            txt = fp.read_text(encoding="utf-8")
            new_txt = re.sub(r"\*\_\w+\_crfuzzer\.(\w+)", f"*_{mode}_crfuzzer.\\1", txt)
            if new_txt != txt:
                fp.write_text(new_txt, encoding="utf-8")
                print(f"[step3] 更新 {fn} glob → *_{mode}_crfuzzer.{{ext}}")

    # 2. 构建（跑 get_oss_fuzzer.sh；提示 build.sh 需已注入编译块）
    if do_build:
        block = None
        bsh = proj_dir / "build.sh"
        if bsh.exists():
            from agent import agent_common as ac
            block = ac.read_marked_block(bsh)
        if not block:
            print("[step3] ⚠️ build.sh 未见 dc-injected 标记块——若未注入编译循环，"
                  "可能只会编到项目自带 harness。可先跑 `python3 -m agent.agent_pipeline "
                  f"{project}` 让注入 agent 处理，或手改 build.sh 的标记块。")
        log_path = agent_main.agent_main_build(project, mode=mode)
        print(f"[step3] 构建完成，log: {log_path}")
    else:
        print("[step3] --no-build：跳过构建，直接比对现有产物")

    # 3. 比对期望 vs 实际（oss-bin/<project>/[<mode>/]）
    built, failed = agent_main.diff_products(project, mode)
    total = len(built) + len(failed)

    print(f"\n[step3] {'=' * 40}")
    print(f"  [{mode or 'legacy'}] driver: {total}  |  编译成功: {len(built)}/{total}"
          f"  ({(len(built) / total * 100) if total else 0:.0f}%)")
    for b in sorted(built):
        print(f"    ✅ {b}")
    for f in sorted(failed):
        print(f"    ❌ {f}")
    if failed:
        print(f"\n  修复失败 driver 请跑: python3 step3_build.py {project}"
              + (f" --mode={mode}" if mode else "")
              + "（默认多 agent 修复循环）")

    summary = {
        "project": project,
        "mode": mode or "legacy",
        "total_count": total,
        "success_count": len(built),
        "success_rate": f"{(len(built) / total * 100) if total else 0:.0f}%",
        "binaries": sorted(built),
        "failed": sorted(failed),
        "path": "deterministic_fallback",
    }
    (intermediate_for(project) / "step3_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


def _parse_args(argv):
    """解析 CLI。返回 (project, opts dict)。"""
    if not argv:
        print(__doc__)
        sys.exit(1)
    project = argv[0]
    no_repair = "--no-repair" in argv
    no_build = "--no-build" in argv
    max_rounds = 3
    mode = None
    for a in argv[1:]:
        if a.startswith("--max-rounds="):
            max_rounds = int(a.split("=", 1)[1])
        elif a.startswith("--mode="):
            mode = a.split("=", 1)[1]
    return project, {
        "no_repair": no_repair,
        "no_build": no_build,
        "max_rounds": max_rounds,
        "mode": mode,
    }


def main():
    project, opts = _parse_args(sys.argv[1:])
    # --no-build 蕴含确定性路径（只比对，不可能进修复循环）
    if opts["no_repair"] or opts["no_build"]:
        build_and_report(project, do_build=not opts["no_build"], mode=opts["mode"])
    else:
        run_repair(project, max_rounds=opts["max_rounds"], mode=opts["mode"])


if __name__ == "__main__":
    main()
