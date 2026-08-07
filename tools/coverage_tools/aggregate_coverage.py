#!/usr/bin/env python3
# aggregate_coverage.py — 四组（origin/focus/peer/cross）覆盖率聚合 + union-vs-k 曲线
#
# 输入：run_cov_experiment.sh 产出的 artifacts/coverage_exp/<TS>/<proj>/{origin,focus,peer,cross}/*.cov.json
#       每个文件形如 {project,group,bin,cov_edges,cov_reported,line_count,func_count,lines[],funcs[]}
#
# 输出（写到 <result_root>/）：
#   summary.json — 结构化：每项目每组的 union-vs-k 曲线 + 满 N 总量
#   summary.md   — 人读对比表（四组曲线 + 对比点 k=min(N)-1）
#
# 主指标：union-vs-k 曲线——每组随机抽 k 个 driver 求覆盖并集，多次取平均，k=1..N
#         对比点取 k = min(N) - 1（产出最少那组在 min(N) 处只有单次实现无法平均，取前一点最稳）
# 副指标：各组满 N 的总量（显式标注 N）
# 跑不了某模式的项目（0 driver）用 n/a，不用空白或 0
#
# 用法：python3 aggregate_coverage.py artifacts/coverage_exp/<TS>
import sys
import os
import json
import glob
import random
from collections import defaultdict

GROUPS = ["origin", "focus", "peer", "cross"]
SAMPLE_TIMES = 20  # 每个 k 抽样次数（取均值±标准差）


def load_group_files(proj_dir, group):
    """读 <proj>/<group>/ 下所有 .cov.json，返回 lines[] 集合列表（每个 binary 一份）。"""
    gdir = os.path.join(proj_dir, group)
    files = sorted(glob.glob(os.path.join(gdir, "*.cov.json")))
    per_bin_lines = []
    for jf in files:
        try:
            with open(jf, "r", errors="replace") as f:
                d = json.load(f)
            per_bin_lines.append(set(d.get("lines", [])))
        except (json.JSONDecodeError, OSError):
            continue
    return per_bin_lines


def union_of_k(per_bin_lines, k):
    """随机抽 k 个求 lines 并集大小。"""
    if k > len(per_bin_lines):
        return None
    sample = random.sample(per_bin_lines, k)
    u = set()
    for s in sample:
        u |= s
    return len(u)


def union_vs_k_curve(per_bin_lines, max_k):
    """算 k=1..max_k 的 union-vs-k 曲线（每个 k 抽 SAMPLE_TIMES 次取均值±标准差）。"""
    curve = []
    for k in range(1, max_k + 1):
        if k > len(per_bin_lines):
            curve.append({"k": k, "mean": None, "std": None, "n": "n/a"})
            continue
        vals = []
        for _ in range(SAMPLE_TIMES):
            v = union_of_k(per_bin_lines, k)
            if v is not None:
                vals.append(v)
        if not vals:
            curve.append({"k": k, "mean": None, "std": None, "n": "n/a"})
            continue
        mean = sum(vals) / len(vals)
        if len(vals) > 1:
            std = (sum((v - mean) ** 2 for v in vals) / len(vals)) ** 0.5
        else:
            std = 0
        curve.append({"k": k, "mean": round(mean, 1), "std": round(std, 1),
                      "n_samples": len(vals)})
    return curve


def main():
    if len(sys.argv) < 2:
        print("用法: python3 aggregate_coverage.py <result_root>")
        sys.exit(1)
    root = sys.argv[1].rstrip("/")
    if not os.path.isdir(root):
        print("[error] 结果目录不存在: %s" % root)
        sys.exit(1)

    # 项目 = root 下含任一 GROUP 子目录的目录
    projects = []
    for name in sorted(os.listdir(root)):
        pdir = os.path.join(root, name)
        if not os.path.isdir(pdir) or name == "raw":
            continue
        if any(os.path.isdir(os.path.join(pdir, g)) for g in GROUPS):
            projects.append(name)

    summary = {"result_root": root, "projects": {}}
    for proj in projects:
        pdir = os.path.join(root, proj)
        proj_entry = {"groups": {}}
        group_bins = {}
        for g in GROUPS:
            per_bin = load_group_files(pdir, g)
            group_bins[g] = per_bin
            n = len(per_bin)
            if n == 0:
                proj_entry["groups"][g] = {"N": 0, "status": "n/a", "curve": []}
            else:
                curve = union_vs_k_curve(per_bin, n)
                # 满 N 总量（副指标）
                full_union = set()
                for s in per_bin:
                    full_union |= s
                proj_entry["groups"][g] = {
                    "N": n,
                    "status": "ok",
                    "curve": curve,
                    "full_union_lines": len(full_union),
                }
        # 对比点 k = min(有数据的组的 N) - 1
        ns = [len(group_bins[g]) for g in GROUPS if len(group_bins[g]) > 0]
        if ns:
            min_n = min(ns)
            compare_k = max(1, min_n - 1)
            proj_entry["compare_point"] = {"k": compare_k, "min_N": min_n}
            # 各组在 compare_k 的均值
            for g in GROUPS:
                curve = proj_entry["groups"][g].get("curve", [])
                if compare_k <= len(curve):
                    pt = curve[compare_k - 1]
                    proj_entry["groups"][g]["at_compare_k"] = pt.get("mean", "n/a")
                else:
                    proj_entry["groups"][g]["at_compare_k"] = "n/a"
        summary["projects"][proj] = proj_entry

    out_json = os.path.join(root, "summary.json")
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    # 人读 md
    lines_md = ["# Coverage Summary (union-vs-k)\n",
                f"result_root: {root}\n\n"]
    for proj, pe in summary["projects"].items():
        lines_md.append(f"## {proj}\n")
        cp = pe.get("compare_point", {})
        lines_md.append(f"对比点 k = {cp.get('k', '?')} (min N = {cp.get('min_N', '?')})\n\n")
        lines_md.append("| group | N | at compare_k | full union |\n|---|---|---|---|\n")
        for g in GROUPS:
            ge = pe["groups"][g]
            n = ge.get("N", 0)
            at_k = ge.get("at_compare_k", "n/a")
            full = ge.get("full_union_lines", "n/a")
            lines_md.append(f"| {g} | {n} | {at_k} | {full} |\n")
        lines_md.append("\n")
    with open(os.path.join(root, "summary.md"), "w") as f:
        f.writelines(lines_md)

    print(f"[aggregate] {len(projects)} 项目 → {out_json}")
    print(f"  summary.md → {os.path.join(root, 'summary.md')}")


if __name__ == "__main__":
    main()
