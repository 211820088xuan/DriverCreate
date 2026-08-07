"""并发跑所有项目的 plan_gen（三模式），按需标触发 LLM 填槽。

按需标设计：plan_gen 的 _fill_slot_candidates 第三轮——签名规则 + 已标 role_labels
不够填槽位时，才批量 LLM 标该批 API（缓存到 role_labels.jsonl + 更新内存）。
不预标全 all_apis，只标槽位实际用到的。

用法：python3 tools/step2_tools/llm_fill_concurrent.py [--workers=6]
"""
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from config import intermediate_for, shared_dir
from contracts.skeletons import load_skeletons
from contracts.plans import save_plan
import plan_gen

PROJECTS = [
    "capstone", "c-blosc2", "draco", "file", "flac", "freetype2", "glog", "h3",
    "harfbuzz", "json-c", "libcoap", "libpsl", "libspng", "libtiff", "lua",
    "mbedtls", "md4c", "mongoose", "ndpi", "re2", "simdjson", "sql-parser",
    "wavpack", "zstd",
]


def run_one_project(proj: str, skeletons_data: dict, num_drivers: int = 5) -> dict:
    """跑一个项目的三模式 plan（共享 role_labels，按需标触发 LLM 填槽）。"""
    scored_path = intermediate_for(proj) / "scored.json"
    if not scored_path.exists():
        return {"proj": proj, "error": "no scored.json"}
    scored_data = json.loads(scored_path.read_text(encoding="utf-8"))
    own_shapes = plan_gen._project_own_shapes(proj)
    # 共享 role_labels dict（按需标时三模式都更新这个 dict + 写文件）
    role_labels = plan_gen._load_role_labels(proj)

    row = {"proj": proj}
    for mode in plan_gen.MODES:
        try:
            if mode == "focus":
                plan = plan_gen._gen_focus_plan(proj, scored_data, own_shapes,
                                                 num_drivers, role_labels=role_labels)
            else:
                plan = plan_gen._gen_peer_cross_plan(
                    proj, mode, scored_data, skeletons_data, own_shapes,
                    num_drivers, role_labels=role_labels)
            save_plan(proj, mode, plan)
            row[mode + "_drv"] = len(plan["drivers"])
            row[mode + "_skip"] = len(plan["skipped"])
        except Exception as e:
            row[mode + "_drv"] = -1
            row[mode + "_skip"] = -1
            row[mode + "_err"] = str(e)[:80]
    return row


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--num-drivers", type=int, default=5)
    args = ap.parse_args()

    skeletons_data = load_skeletons()
    print(f"[并发 plan_gen] {len(PROJECTS)} 项目 / 并发 {args.workers} / "
          f"骨架池 {len(skeletons_data['skeletons'])} 条 / 按需标模式")
    print("  注：按需标——_fill_slot_candidates 槽位填不够时才 LLM 标该批 API")

    summary = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_one_project, p, skeletons_data, args.num_drivers): p
                   for p in PROJECTS}
        for f in as_completed(futures):
            try:
                row = f.result()
                summary.append(row)
                done += 1
                proj = row["proj"]
                print(f"  [{done}/{len(PROJECTS)}] {proj:<14} "
                      f"focus={row.get('focus_drv','?')}/{row.get('focus_skip','?')} "
                      f"peer={row.get('peer_drv','?')}/{row.get('peer_skip','?')} "
                      f"cross={row.get('cross_drv','?')}/{row.get('cross_skip','?')}"
                      f"{(' err=' + row['focus_err']) if row.get('focus_err') else ''}")
            except Exception as e:
                done += 1
                print(f"  [future] 失败: {e}")

    # Gate 2 统计
    print("\n=== Gate 2 统计 ===")
    cross_drvs = [r["cross_drv"] for r in summary if r.get("cross_drv", -1) >= 0]
    ge3 = [r for r in summary if r.get("cross_drv", -1) >= 3]
    print(f"项目数: {len(summary)}")
    if cross_drvs:
        print(f"cross 平均/项目: {sum(cross_drvs) / len(cross_drvs):.2f}")
    print(f"cross ≥3 的项目数: {len(ge3)} / {len(summary)}")
    gate_avg = sum(cross_drvs) / len(cross_drvs) >= 3 if cross_drvs else False
    gate_dist = len(ge3) >= 6
    print(f"Gate 2: 平均≥3 {'✅' if gate_avg else '❌'}  且 ≥3项目数≥6 {'✅' if gate_dist else '❌'}")

    # role_labels.jsonl 最终条目数
    rp = shared_dir() / "role_labels.jsonl"
    if rp.exists():
        n = sum(1 for line in rp.read_text(encoding="utf-8").splitlines() if line.strip())
        print(f"role_labels.jsonl: {n} 条")


if __name__ == "__main__":
    main()
