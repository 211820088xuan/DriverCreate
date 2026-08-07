#!/usr/bin/env python3
"""
Step 1: 项目情报收集 — 图谱情报 + 驱动模板 + 构建参数 + API 打分

阶段2 拆分后只保留 main() 编排：
  A 图谱情报 (Neo4j)        → tools/step1_tools/graph_query.py      → setup.json
  B 驱动模板提取             → tools/step1_tools/driver_template.py → template.json
  C 构建 Profile 提取        → tools/step1_tools/build_profile.py   → build_profile.json
  D API 分类 & 打分           → tools/step1_tools/api_scoring.py     → scored.json

输入: project_name
输出: intermediate/<project>/ 下的 setup.json, template.json, build_profile.json, scored.json
"""

import sys
import os

from config import INTERMEDIATE_DIR, SRC_DIR, intermediate_for
# 源码自动克隆（与 step3_build 同源，幂等：目录已存在则直接返回 True）
from tools.step3_agent import agent_main
from tools.step1_tools.graph_query import run_graph_setup
from tools.step1_tools.driver_template import run_template_extraction
from tools.step1_tools.build_profile import run_build_profile
from tools.step1_tools.api_scoring import run_api_scoring

# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

def main():
    if len(sys.argv) < 2:
        print("Usage: python step1_prepare.py <project_name>")
        sys.exit(1)

    project = sys.argv[1]
    os.makedirs(INTERMEDIATE_DIR, exist_ok=True)
    os.makedirs(SRC_DIR, exist_ok=True)
    proj_dir = intermediate_for(project)

    print(f"[Step1] 开始为 {project} 收集情报...")

    # 源码就绪 (non-fatal): 早于 B/C/step2 —— 它们都依赖 source_code/<project>。
    # 此前 clone 只在 step3 触发，导致新项目首跑时 step2 因源码缺失退出（total=0）。
    # 克隆失败不致命：A 段图谱情报不依赖源码，且 step3 仍有兜底调用。
    try:
        if agent_main.ensure_source_code(project):
            print(f"  [ensure_source] source_code/{project} 就绪")
        else:
            print(f"  [ensure_source] ⚠️ source_code/{project} 缺失且克隆失败，"
                  f"B/C/step2 可能降级，继续收集图谱情报...")
    except Exception as e:
        print(f"  [ensure_source] ⚠️ 克隆异常: {e}，继续...")

    # A: 图谱情报 (fatal)
    try:
        setup_data = run_graph_setup(project)
    except Exception as e:
        print(f"[ERROR] 图谱情报查询失败: {e}")
        sys.exit(1)

    # B: 模板提取 (non-fatal)
    try:
        template_data = run_template_extraction(project, setup_data)
    except Exception as e:
        print(f"[WARN] 模板提取失败: {e}")
        template_data = {}

    # C: 构建 Profile (non-fatal)
    try:
        run_build_profile(project, template_data)
    except Exception as e:
        print(f"[WARN] 构建 Profile 失败: {e}")

    # D: API 打分 (non-fatal)
    try:
        run_api_scoring(project, setup_data)
    except Exception as e:
        print(f"[WARN] API 打分失败: {e}")

    # 汇总
    print(f"\n[Step1] {project} 情报就绪 → {proj_dir}/")
    for f in sorted(proj_dir.glob("*.json")):
        print(f"  {f.name}")


if __name__ == "__main__":
    main()