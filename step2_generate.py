#!/usr/bin/env python3
"""
Step 2: LLM 生成 fuzz driver（骨架驱动，plan 填槽）

阶段3 拆分后只保留 main 编排 + 6 个入口/辅助函数；组件拆至 tools/step2_tools/：
  llm_client（LLM 调用+代码提取）/ signature_cache（签名缓存）/
  validators（L1-L4 校验）/ context_builder（用法范例+版本+模板段落）/
  prompt_builder（plan→prompt）。

保留函数：load_template / derive_driver_name / _derive_name_fallback /
  generate_one_driver_from_plan / _run_peer_cross_mode / main。

输入: project_name
依赖: intermediate/<project>/scored.json, template.json（step1 产出）
输出: output/<project>/driver/<mode>/*_<mode>_crfuzzer.{c,cpp} + manifest.json
"""

import sys
import json
import os
import re
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import (
    INTERMEDIATE_DIR, OUTPUT_DIR, SRC_DIR,
    LLM_PROVIDER, DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_FAST_MODEL,
    VENDOR_SKIP_DIRS, MODES, ROLES,
    intermediate_for, output_for, plan_path,
)
from contracts.plans import load_plan, PLAN_VERSION

from tools.step2_tools.llm_client import call_llm, extract_code, is_valid_driver
from tools.step2_tools.signature_cache import build_signature_cache, _sig_names
from tools.step2_tools.validators import validate_driver_includes, validate_platform_headers, validate_driver_calls, validate_driver_types, _load_fh_data
from tools.step2_tools.prompt_builder import build_prompt_from_plan

# ─── Phase A: 模板处理 ────────────────────────────────────────────

def load_template(project):
    """加载 step1 提取的模板"""
    template_file = INTERMEDIATE_DIR / project / "template.json"
    if template_file.exists():
        return json.loads(template_file.read_text())
    return {}


def derive_driver_name(sequence, template_data, project, existing_names=None):
    """从 API 调用序列生成简洁有意义的 driver 名称"""
    if existing_names is None:
        existing = set()
    else:
        existing = existing_names

    name = _derive_name_fallback(sequence, project)

    base = name
    suffix = 2
    while name in existing:
        stem = re.sub(r'_v\d+_crfuzzer$', '_crfuzzer', base)
        stem = stem.replace('_crfuzzer', '')
        name = f"{stem}_v{suffix}_crfuzzer"
        suffix += 1

    existing.add(name)
    return name


def _derive_name_fallback(sequence, project):
    """无 LLM 时的回退命名: 从 API 序列提取关键词"""
    primary = [s["api"] for s in sequence if s.get("untested")][:3]
    if not primary:
        primary = [s["api"] for s in sequence[:3]]

    # 尝试提取有意义的词
    for api in primary:
        # snake_case: 取第二部分
        parts = api.split('_')
        for p in parts[1:3]:
            if len(p) >= 3 and p.lower() not in ('new', 'get', 'set', 'free', 'init', 'add', 'del'):
                return f"{p.lower()}_crfuzzer"
        # CamelCase: xmlNewDoc → new_doc
        words = re.findall(r'[A-Z][a-z]+', api)
        meaningful = [w.lower() for w in words
                      if w.lower() not in ('new', 'get', 'set', 'free', 'init', 'add', 'del')]
        if meaningful:
            return f"{'_'.join(meaningful[:2])}_crfuzzer"

    return f"{project.replace('-', '_')}_crfuzzer"




def generate_one_driver_from_plan(args):
    """plan 驱动的单 driver 生成（替代旧 generate_one_driver）。

    args = (project, mode, plan_driver, template_data, src_dir_str,
            driver_idx, api_key, base_url, fast_model, strong_model, provider)
    返回 (code, plan_driver_id, driver_idx, mode, lang, file_hint)
    """
    (project, mode, plan_driver, template_data, src_dir_str,
     driver_idx, api_key, base_url, fast_model, strong_model, provider) = args

    try:
        prompt, lang, file_hint = build_prompt_from_plan(
            project, mode, plan_driver, template_data, src_dir_str)
    except Exception as e:
        print(f"  [{mode}#{driver_idx}] prompt 构建失败: {e}")
        return (None, plan_driver.get("id"), driver_idx, mode, "c", "")

    drv_id = plan_driver.get("id", f"{mode}#{driver_idx}")
    print(f"  [{drv_id}] {mode} 生成中...")

    code = None
    # Stage 1: 快模型 3 次
    for attempt in range(3):
        response = call_llm(prompt, fast_model, api_key, base_url, provider)
        if not response:
            continue
        code = extract_code(response)
        if is_valid_driver(code):
            print(f"  [{drv_id}] ✅ 快模型成功 ({len(code.splitlines())} 行)")
            break
        code = None

    # Stage 2: 强模型兜底 3 次
    if code is None:
        for attempt in range(3):
            response = call_llm(prompt, strong_model, api_key, base_url, provider)
            if not response:
                continue
            code = extract_code(response)
            if is_valid_driver(code):
                print(f"  [{drv_id}] ✅ 强模型成功 ({len(code.splitlines())} 行)")
                break
            code = None

    if code is None:
        print(f"  [{drv_id}] ❌ 均失败")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    # ── 校验器（Phase 8: 恢复 L2/L3 拦截）──
    # L1: include 白名单（仍拦截）
    inc_ok, inc_violations = validate_driver_includes(code, project)
    if not inc_ok:
        print(f"  [{drv_id}] ❌ L1 include 违规: {inc_violations[:3]}")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    # L4: 平台头（仍拦截）
    plat_ok, plat_violations = validate_platform_headers(code)
    if not plat_ok:
        print(f"  [{drv_id}] ❌ L4 平台头冲突: {plat_violations[:3]}")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    # L2: 臆造调用（降级警告：白名单不全会导致标准库函数误拦，让 build 阶段兜底）
    sig_cache = build_signature_cache(src_dir_str)
    fh_data = _load_fh_data(project)
    call_ok, fake_calls, blk_hits = validate_driver_calls(code, project, sig_cache, fh_data)
    if not call_ok:
        print(f"  [{drv_id}] ⚠️ [L2 警告] 疑似臆造调用: {sorted(fake_calls)[:5]}，照常保存（build 阶段兜底）")

    # L3: 类型可见性（Phase 8: 恢复拦截）
    type_ok, invisible_types = validate_driver_types(code, project, sig_cache)
    if not type_ok:
        print(f"  [{drv_id}] ❌ L3 不可见类型: {sorted(invisible_types)[:5]}")
        return (None, drv_id, driver_idx, mode, lang, file_hint)

    return (code, drv_id, driver_idx, mode, lang, file_hint)


# ─── Main ───────────────────────────────────────────────────────────

def _run_peer_cross_mode(project, mode, template_data, src_dir,
                         target_count, api_key, base_url, fast_model, strong_model):
    """plan 驱动模式（focus/peer/cross 通用）。

    加载 plan_<mode>.json → build_prompt_from_plan → LLM 生成 → L1/L4 硬拦 + L2 警告 + L3 硬拦。
    产出 driver 到 output/<project>/driver/<mode>/*_<mode>_crfuzzer.{ext}。
    """
    try:
        plan = load_plan(project, mode)
    except Exception as e:
        print(f"  [{mode}] plan 加载失败: {e}")
        return []

    plan_drivers = plan.get("drivers", [])[:target_count]
    if not plan_drivers:
        print(f"  [{mode}] plan 无 driver")
        return []

    worker_args = [
        (project, mode, pd, template_data, str(src_dir),
         i, api_key, base_url, fast_model, strong_model, LLM_PROVIDER)
        for i, pd in enumerate(plan_drivers)
    ]

    max_workers = max(1, min(target_count, int(os.getenv("STEP2_MAX_WORKERS", "8"))))
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(generate_one_driver_from_plan, args): args[4]
                   for args in worker_args}
        for future in as_completed(futures):
            try:
                code, drv_id, idx, m, lang, file_hint = future.result()
                results.append((code, drv_id, idx, m, lang, file_hint))
            except Exception as e:
                print(f"  [{mode}] worker 异常: {e}")

    mode_out = output_for(project, mode)
    mode_out.mkdir(parents=True, exist_ok=True)
    generated = []
    for code, drv_id, idx, m, lang, file_hint in results:
        if code is None:
            continue
        ext = file_hint.split(".")[-1] if file_hint else ("cpp" if lang == "cpp" else "c")
        name = file_hint.rsplit(".", 1)[0] if file_hint else f"{project}_{mode}_{idx}_crfuzzer"
        if f"_{mode}_crfuzzer" not in name:
            name = f"{name}_{mode}_crfuzzer"
        out_file = mode_out / f"{name}.{ext}"
        out_file.write_text(code)
        generated.append({"mode": mode, "name": name, "file": str(out_file),
                          "driver_id": drv_id})
        print(f"  [{drv_id}] ✅ {name} → {out_file}")
    return generated


def main():
    if len(sys.argv) < 2:
        print("Usage: python step2_generate.py <project> [num_drivers=5] [--mode=focus|peer|cross|all]")
        sys.exit(1)

    project = sys.argv[1]
    target_count = 5
    modes = list(MODES)
    for a in sys.argv[2:]:
        if a.startswith("--mode="):
            m = a.split("=", 1)[1]
            if m == "all":
                modes = list(MODES)
            elif m in MODES:
                modes = [m]
            else:
                print(f"[Step2] --mode 非法: {m}")
                sys.exit(1)
        elif a.isdigit():
            target_count = int(a)

    proj_dir = intermediate_for(project)
    scored_file = proj_dir / "scored.json"
    if not scored_file.exists():
        print(f"[Step2] 错误: {scored_file} 不存在，请先运行 step1_prepare.py")
        sys.exit(1)

    scored_data = json.loads(scored_file.read_text())
    template_data = load_template(project) or {}
    src_dir = SRC_DIR / project
    if not src_dir.exists():
        print(f"[Step2] 错误: 源码目录 {src_dir} 不存在")
        sys.exit(1)

    _api_key = DEEPSEEK_API_KEY
    _base_url = DEEPSEEK_BASE_URL
    _fast_model = DEEPSEEK_FAST_MODEL
    _strong_model = DEEPSEEK_MODEL

    print(f"\n[Step2] 骨架驱动生成 | 项目={project} | 模式={modes} | "
          f"每模式上限={target_count}")
    print(f"  三模式统一走 plan 驱动（build_prompt_from_plan + L2/L3 拦截）")

    sig_cache = build_signature_cache(str(src_dir))
    print(f"  签名缓存: {len(_sig_names(sig_cache))} 个")

    all_generated = []
    for mode in modes:
        print(f"\n[Step2] [{mode}] 生成中...")
        generated = _run_peer_cross_mode(project, mode, template_data,
                                         src_dir, target_count,
                                         _api_key, _base_url,
                                         _fast_model, _strong_model)
        all_generated.extend(generated)

    # ── manifest ──
    manifest = {
        "project": project,
        "modes": modes,
        "num_generated": len(all_generated),
        "fast_model": _fast_model,
        "strong_model": _strong_model,
        "drivers": [{"mode": g["mode"], "name": g["name"], "file": g["file"]}
                    for g in all_generated],
    }
    manifest_file = proj_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

    print(f"\n[Step2] {'='*40}")
    print(f"  生成: {len(all_generated)} 个 driver | 模式: {modes}")
    for g in all_generated:
        print(f"    [{g['mode']}] ✅ {g['name']}")


if __name__ == "__main__":
    main()