#!/usr/bin/env python3
"""Step2 prompt 构建：从 plan 骨架槽位 + 上下文段落 → LLM prompt。"""
# 从 step2_generate.py 阶段3 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import os
from config import INTERMEDIATE_DIR
from tools.step2_tools.signature_cache import build_signature_cache, load_scored_signatures, _format_scored_sig, lookup_signatures, build_header_api_map, extract_helper_signatures, format_constants_section
from tools.step2_tools.context_builder import find_usage_examples, load_project_role_distribution, load_skeleton_source_info, _find_complete_driver_examples, build_version_section, build_template_section

def build_prompt_from_plan(project, mode, plan_driver, template_data, src_dir):
    """从 plan_<mode>.json 的单个 driver 项构造 prompt（§8.3）——旧 build_prompt 上下文超集。

    在旧 build_prompt 的全部上下文（template/constants/version/fuzzing_headers/
    header_map/usage_examples）基础上，把 sequence_section 换成 plan 骨架槽位。
    范例按 §7.2：focus 给本项目源码 / peer 给同场景源码 / cross 不给。
    """
    skeleton = plan_driver.get("skeleton", [])
    slots = plan_driver.get("slots", [])
    lang = (template_data.get("dominant_lang") or "c")
    ext = "cpp" if lang == "cpp" else "c"
    code_block = "cpp" if lang == "cpp" else "c"
    is_cpp = lang == "cpp"

    # 收集槽位候选 API 名（供 header_map/constants 等复用旧 helper）
    api_names = []
    for s in slots:
        for c in s.get("candidates", []):
            if c.get("api"):
                api_names.append(c["api"])
    api_names = list(dict.fromkeys(api_names))  # 去重保序

    # 签名缓存（供 constants/header_map/types 用）
    sig_cache = build_signature_cache(str(src_dir))
    scored_sigs = load_scored_signatures(project)
    signatures = lookup_signatures(sig_cache, api_names, scored_sigs)
    # KG 富化签名优先：用 _format_scored_sig 格式化（签名 + description），保留用途信息
    scored_data_path = INTERMEDIATE_DIR / project / "scored.json"
    api_meta = {}
    if scored_data_path.exists():
        sd = json.loads(scored_data_path.read_text())
        api_meta = {s["api"]: s for s in sd.get("scored_apis", [])}
        for name in api_names:
            meta = api_meta.get(name)
            if meta and meta.get("signature"):
                signatures[name] = _format_scored_sig(name, meta)

    # ── 1. lang_guide（C/C++ 分支，详细约束，无项目特定示例）──
    if is_cpp:
        lang_guide = f"""你的任务：为 OSS-Fuzz 项目 **{project}** 编写一个 **C++ libFuzzer fuzz driver**（harness），文件后缀 `.{ext}`。

【注意】**关键约束**：本项目的示例 driver 全部是 **C++** 文件，你生成的 driver 也必须是 **C++** 代码。

该 fuzz driver 将在 OSS-Fuzz 的 Docker 构建环境（clang + AddressSanitizer + `LIB_FUZZING_ENGINE=-fsanitize=fuzzer`）中编译，由 libFuzzer coverage-guided fuzzing 持续运行，发现 {project} 的 heap-buffer-overflow、use-after-free、integer-overflow 等内存安全 bug。

## 【注意】C++ 特定要求（严格执行，违反将导致编译失败）

1. **入口函数**: `extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`（必须有 `extern "C"` 防 name mangling）

2. **不透明结构体**: 如果 API 接收 `SomeType *`，必须用工厂函数（`SomeType_new()` / `SomeType_create()`）分配，用 `SomeType_free()` / `SomeType_destroy()` 释放；绝不传 nullptr 给不透明指针参数；禁止 `struct xxx var;` 栈分配未知大小类型

3. **参数严格匹配**: 调用任何 API 前必须从 signature 读取确切参数数量和类型，禁止猜测；如示例/签名有 N 个参数，必须传 N 个

4. **goto 安全**: 如用 goto 清理资源，不跨越变量声明作用域；提前声明所有需要的变量

5. **输入数据处理**: 可用 `FuzzedDataProvider`（`#include <fuzzer/FuzzedDataProvider.h>`），或继承项目 Stream/Decoder 类并实现回调，或手动解析 `data` 字节数组

6. **禁止调用内部/测试工具函数**: 只用公开 API；不要 include `oss-fuzz/common.h` 等内部测试头

7. **返回值检查**: 每个返回指针的函数必须检查 nullptr，返回错误码的检查非零值；错误路径必须释放已分配资源后 `return 0`

8. **资源释放**: 所有通过库 API 分配的资源（handle、buffer、context）必须在所有 return 路径上释放，避免 LeakSanitizer 误报

按上方骨架序列顺序构造调用，每槽**只用候选 API**（不要调用候选之外的其他 API）。
每个 API 必须严格按 signature 的参数数量传参——数 signature 括号内的参数个数，
传错数量（too few/many arguments）会导致编译失败。参数从 signature 读取，不要猜。"""
    else:
        lang_guide = f"""你的任务：为 OSS-Fuzz 项目 **{project}** 编写一个 **纯 C libFuzzer fuzz driver**（harness），文件后缀 `.{ext}`。

【注意】**关键约束**：生成的 driver 必须是 **纯 C** 代码，不得使用 C++ 特性。

该 fuzz driver 将在 OSS-Fuzz 的 Docker 构建环境（clang + AddressSanitizer + `LIB_FUZZING_ENGINE=-fsanitize=fuzzer`）中编译，由 libFuzzer coverage-guided fuzzing 持续运行，发现 {project} 的 heap-buffer-overflow、use-after-free、integer-overflow 等内存安全 bug。

## 【注意】C 特定要求

1. **入口函数**: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`

2. **输入切分**: 只能用 `data[i]` 索引 + `size` 边界检查；如需字符串，手动 `memcpy` 后补 `\\0`；不能使用 FuzzedDataProvider

3. **禁止不透明类型栈分配**: 头文件中仅有前向声明（`struct xxx;`）的类型只能用指针操作，必须通过工厂函数分配，禁止 `struct xxx var;` 栈分配

4. **参数数量和类型必须精确**: 调用每个 API 时参数个数、顺序、类型必须与函数签名严格一致，禁止猜测

5. **禁止 C++ 特性**: 不要使用 class、template、namespace、iostream、new/delete、std:: 等

6. **不透明结构体指针**: 如果 API 接收 `SomeType *`，必须先用 `SomeType_new()` / `SomeType_alloc()` 等工厂函数分配后传入；绝不传 NULL 给不透明指针参数

7. **返回值检查**: 每个返回指针的函数必须检查 NULL，返回错误码的函数必须检查非零值；错误路径必须释放已分配资源后 `return 0`

8. **资源释放**: 所有通过库 API 分配的资源（handle、buffer、context）必须在所有 return 路径上释放，避免 LeakSanitizer 误报

按上方骨架序列顺序构造调用，每槽**只用候选 API**（不要调用候选之外的其他 API）。
每个 API 必须严格按 signature 的参数数量传参——数 signature 括号内的参数个数，
传错数量（too few/many arguments）会导致编译失败。参数从 signature 读取，不要猜。"""

    # ── 2. build_info（复用旧逻辑）──
    build_info = ""
    bp_path = INTERMEDIATE_DIR / project / "build_profile.json"
    if bp_path.exists():
        try:
            build_profile = json.loads(bp_path.read_text())
            inc_dirs = build_profile.get("include_dirs", [])
            if inc_dirs:
                build_info += "\n## 构建环境 (include 路径)\n" + "\n".join(f"- {d}" for d in inc_dirs[:8])
            build_info += f"\n**编译器**: {build_profile.get('preferred_compiler', 'clang')}"
            build_info += f"\n**构建系统**: {build_profile.get('build_system', 'unknown')}\n"
        except Exception:
            pass

    # ── 3. header_info（只列公开 header：include/ 目录或顶层 .h，跳过内部子目录）
    header_files = []
    src = Path(src_dir)
    if src.exists():
        for root, dirs, files in os.walk(src):
            dirs[:] = [d for d in dirs if d not in {'.git', 'tests', 'test', 'examples', 'bench'}]
            for f in files:
                if f.endswith('.h'):
                    rel = os.path.relpath(os.path.join(root, f), src)
                    # 跳过内部子目录（blosc/、plugins/、internal/ 等）
                    if rel.startswith(("blosc/", "plugins/", "internal/", "private/")):
                        continue
                    # 只保留 include/ 下的或顶层 .h（公开 header）
                    if rel.startswith("include/") or rel.count(os.sep) == 0:
                        clean = rel[len("include/"):] if rel.startswith("include/") else rel
                        header_files.append(clean)
            if len(header_files) > 20:
                break
    header_info = "\n".join(f"- {h}" for h in sorted(set(header_files))[:20])

    # ── 4. fuzzing_headers_section（复用旧逻辑：含 helper API 清单）──
    fuzzing_headers_section = ""
    fh_path = INTERMEDIATE_DIR / project / "fuzzing_headers.json"
    if fh_path.exists():
        try:
            fh_data = json.loads(fh_path.read_text())
            required = fh_data.get("required_headers", [])
            optional = fh_data.get("optional_headers", [])
            if required:
                fuzzing_headers_section = "\n## 【注意】Fuzzing 基础设施头文件（必须 include）\n\n"
                for h in required:
                    hpath = Path(h['path']).name
                    fuzzing_headers_section += f"- `#include \"{hpath}\"` — {h.get('reason','')}\n"
            # include 白名单
            allowed_headers = set()
            for h in required: allowed_headers.add(Path(h['path']).name)
            for h in optional: allowed_headers.add(Path(h['path']).name)
            if allowed_headers:
                fuzzing_headers_section += "\n## 头文件白名单（只允许 include 以下）\n"
                for h in sorted(allowed_headers)[:30]:
                    fuzzing_headers_section += f"- `{h}`\n"
            # helper API 清单（复用旧逻辑的 extract_helper_signatures）
            helper_sigs = extract_helper_signatures(fh_data)
            if helper_sigs:
                fuzzing_headers_section += "\n## 可用 Helper 函数/宏清单\n"
                for hname, sigs in helper_sigs.items():
                    fuzzing_headers_section += f"### {hname} 提供\n```c\n" + "\n".join(sigs[:10]) + "\n```\n"
        except Exception as e:
            print(f"  [warn] fuzzing_headers 加载失败: {e}")

    # ── 5. header_map_section（复用旧逻辑：API→头文件精确映射）──
    header_api_map = build_header_api_map(str(src_dir), api_names)
    header_map_lines = [f"- `{name}` → `#include <{header_api_map.get(name)}>`"
                        for name in api_names if header_api_map.get(name)]
    header_map_section = ("## API→头文件精确映射\n" + "\n".join(header_map_lines[:30]) + "\n") if header_map_lines else ""

    # ── 6. constants_section（复用旧逻辑：枚举/typedef）──
    constants_section = format_constants_section(sig_cache, api_names)

    # ── 7. version_section（复用旧逻辑）──
    version_section = build_version_section(src_dir)

    # ── 8. template_section（复用旧逻辑：init/cleanup 模式）──
    template_section = build_template_section(template_data)

    # ── 9. sequence_section —— 换成 plan 骨架槽位（核心改动）──
    def _param_count(sig: str) -> int:
        """从签名提取参数数量（数顶层逗号）。"""
        if "(" not in sig or ")" not in sig:
            return -1
        inner = sig[sig.index("(") + 1: sig.rindex(")")]
        inner = inner.strip()
        if not inner or inner == "void":
            return 0
        # 粗切顶层逗号（不处理嵌套括号的边界情况，够用）
        depth = 0
        n = 1
        for ch in inner:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                n += 1
        return n

    skel_lines = ["## 骨架调用序列（按此顺序构造 driver，每槽用候选 API 填充）\n"]
    skel_lines.append("**【严格约束】只允许调用下方每个 slot 列出的候选 API，"
                      "不要调用其他任何 API（包括看似相关的变体）。"
                      "每个 API 必须严格按 signature 的参数数量传参——"
                      "too few/many arguments 会导致编译失败。**\n")
    for idx, role in enumerate(skeleton):
        slot = next((s for s in slots if s.get("index") == idx), None)
        fc = slot.get("fill_count", [1, 1]) if slot else [1, 1]
        cands = slot.get("candidates", []) if slot else []
        skel_lines.append(f"{idx+1}. **{role}** (填 {fc[0]}-{fc[1]} 个 API):")
        if cands:
            for c in cands[:3]:
                sig = signatures.get(c["api"], c.get("signature", ""))
                hdr = c.get("header", "") or (header_api_map.get(c["api"]) or "")
                np = _param_count(sig)
                np_tag = f"（必须传 {np} 个参数）" if np >= 0 else ""
                skel_lines.append(f"   - `{c['api']}`{np_tag} — `{sig}` (header: {hdr})")
        else:
            skel_lines.append(f"   - (无候选，从本项目已测 API 中选一个 {role} 角色的补)")
    sequence_section = "\n".join(skel_lines)

    # ── 10. usage_section（基础质量段：本项目完整范例 + 每 API snippets，三模式都有）
    usage_section = ""
    # 本项目完整范例（基础段，三模式都给——帮 LLM 理解本项目 API 调用范式）
    examples = _find_complete_driver_examples(project, lang)
    if examples:
        usage_section = "\n## 【参考代码】本项目已验证 driver（基础参考，必读）\n"
        for ex in examples[:1]:
            usage_section += f"### `{ex['file']}` ({ex['lines']} 行)\n```{ex['lang']}\n{ex['code'][:8000]}\n```\n"

    # 每 API usage snippet（基础段，三模式都给——真实 API 调用片段，非完整模板）
    snippets = find_usage_examples(project, api_names, max_snippets=15)
    if snippets:
        usage_section += "\n## 候选 API 的正确用法（参考，每段只示范单 API 调用）\n"
        shown_apis = set()
        for s in snippets:
            api = s.get("api")
            if api in api_names and api not in shown_apis:
                shown_apis.add(api)
                snippet_lang = "cpp" if s.get("is_cpp") else "c"
                src_tag = s.get("source_tag", "")
                usage_section += f"### `{api}` 用法 (来自 {s.get('file','')}{src_tag}):\n```{snippet_lang}\n{s['code'][:1500]}\n```\n"
            if len(shown_apis) >= 8:
                break

    # ── 11. 差异化侧重段（按模式注入不同引导信息）──
    mode_section = ""
    if mode == "focus":
        # focus 侧重：未测 API 位置提示（plan evidence 已含插入理由 + 未测 API 角色分布）
        evidence_why = plan_driver.get("evidence", {}).get("why", "")
        mode_section = "\n## 【focus 模式侧重】未测 API 插入指引\n"
        if evidence_why:
            mode_section += f"**插入理由**: {evidence_why}\n"
        # 本项目未测 API 按角色分组（从 role_labels 取，scored.json coverage=0 的子集）
        role_dist = load_project_role_distribution(project)
        if role_dist:
            mode_section += "\n**本项目 API 角色分布**（用于在空 slot 按角色选 API）:\n"
            for role in ("create", "configure", "process", "data_sink", "destroy"):
                apis = role_dist.get(role, [])
                if apis:
                    mode_section += f"- {role}: {', '.join(apis[:8])}{' ...' if len(apis)>8 else ''}\n"
    elif mode == "peer":
        # peer 侧重：同场景项目 API 角色分布 + 调用模式摘要（不给同场景完整范例，防语料污染）
        peer_projects = [p.get("name", "") for p in (template_data.get("peer_projects") or [])[:3] if p.get("name")]
        mode_section = "\n## 【peer 模式侧重】同场景项目 API 组织方式参考\n"
        if peer_projects:
            mode_section += f"**同场景标杆项目**: {', '.join(peer_projects)}\n"
        # 本项目 API 角色分布（帮 LLM 理解骨架 slot 的语义角色）
        role_dist = load_project_role_distribution(project)
        if role_dist:
            mode_section += "\n**本项目 API 角色分布**（骨架 slot 角色对应这些 API）:\n"
            for role in ("create", "configure", "process", "data_sink", "destroy"):
                apis = role_dist.get(role, [])
                if apis:
                    mode_section += f"- {role} ({len(apis)} 个): {', '.join(apis[:6])}{' ...' if len(apis)>6 else ''}\n"
        # slot 填充率提示
        empty_slots = [s for s in slots if not s.get("candidates")]
        if empty_slots:
            mode_section += f"\n**注意**: {len(empty_slots)} 个 slot 无候选 API，需按 slot 的 role 自行从上方角色分布选 API\n"
    elif mode == "cross":
        # cross 侧重：骨架来源场景说明 + 跨场景适配指引 + 本项目 API 角色标签
        skel_id = plan_driver.get("skeleton_id", "")
        sk_info = load_skeleton_source_info(skel_id)
        mode_section = "\n## 【cross 模式侧重】跨场景骨架迁移指引\n"
        # 1. 骨架来源场景说明
        mode_section += f"**骨架来源**: `{skel_id}` (distance_to_own={plan_driver.get('distance_to_own','?')})\n"
        if sk_info:
            mode_section += f"- **骨架序列**: {' → '.join(sk_info.get('sequence', []))}\n"
            mode_section += f"- **支持 driver 数**: {sk_info.get('support_drivers', 0)}\n"
            support_projects = sk_info.get("support_projects", [])
            if support_projects:
                mode_section += f"- **来源项目类型**: {', '.join(support_projects[:6])}\n"
            scenarios = sk_info.get("scenarios", {})
            if scenarios:
                top_scenarios = sorted(scenarios.items(), key=lambda x: -x[1])[:3]
                mode_section += f"- **主要场景**: {', '.join(f'{s}({c})' for s,c in top_scenarios)}\n"
            mode_section += f"- **场景置信度**: {sk_info.get('scenario_confidence', '?')}\n"
        # 2. 跨场景适配指引
        mode_section += "\n**跨场景适配指引**:\n"
        mode_section += "- 该骨架源自其他场景项目，slot 角色是抽象的；需把抽象 slot 映射到本项目对应角色的 API\n"
        mode_section += "- 语义对齐: process slot 在压缩库→压缩/解压 API；在图像库→解码 API；在协议库→解析 API\n"
        mode_section += "- data_sink slot: 接收 fuzzer 输入字节的 API（如 write/feed/parse）\n"
        mode_section += "- 空 slot 时按 role 从下方本项目角色分布选 API，不要臆造不存在的 API\n"
        # 3. 本项目 API 角色标签分布
        role_dist = load_project_role_distribution(project)
        if role_dist:
            mode_section += "\n**本项目 API 角色标签分布**（按角色填 slot）:\n"
            for role in ("create", "configure", "process", "data_sink", "destroy"):
                apis = role_dist.get(role, [])
                if apis:
                    mode_section += f"- {role} ({len(apis)} 个): {', '.join(apis[:6])}{' ...' if len(apis)>6 else ''}\n"
        # slot 填充率提示
        empty_slots = [s for s in slots if not s.get("candidates")]
        if empty_slots:
            mode_section += f"\n**注意**: {len(empty_slots)} 个 slot 无候选 API，需按 slot 的 role + 上方角色分布自行选 API\n"

    # 文件名提示（id_suffix 放 mode 前，保持 _crfuzzer 结尾以匹配 step3 glob）
    first_cand = ""
    for s in slots:
        if s.get("candidates"):
            first_cand = s["candidates"][0]["api"].replace("-", "_")
            break
    # driver_id 形如 "focus#1"，取 # 后数字做后缀
    drv_id = plan_driver.get("id", "")
    id_suffix = ""
    if "#" in drv_id:
        id_suffix = drv_id.rsplit("#", 1)[1]
    name_part = first_cand if first_cand else project
    if id_suffix:
        file_hint = f"{name_part}_{id_suffix}_{mode}_crfuzzer.{ext}"
    else:
        file_hint = f"{name_part}_{mode}_crfuzzer.{ext}"

    # 项目背景
    scenario = ""
    peer_projects_list = []
    if scored_data_path.exists():
        sd = json.loads(scored_data_path.read_text())
        scenario = sd.get("scenario", "")
        peer_projects_list = [p.get("name", "") for p in (sd.get("peer_projects") or [])[:3] if p.get("name")]

    peer_projects_str = ", ".join(peer_projects_list) if peer_projects_list else "无"

    prompt = f"""{lang_guide}

## 项目背景
- **库**: {project}
- **场景**: {scenario}
- **模式**: {mode}
- **骨架来源**: {plan_driver.get('skeleton_id', '?')} (distance_to_own={plan_driver.get('distance_to_own', '?')})
- {plan_driver.get('evidence', {}).get('why', '')}
- **同场景标杆项目**: {peer_projects_str}

{build_info}

## 主要头文件
{header_info}

{fuzzing_headers_section}
{header_map_section}
{constants_section}
{version_section}

{template_section}

{sequence_section}

{usage_section}
{mode_section}
## 生成要求

请生成完整的 libFuzzer fuzz driver 源文件，文件名 `{file_hint}`：

1. **按骨架顺序**: 严格按上方骨架序列顺序构造调用。每槽用候选 API 填充（参数从 signature 读取，不要猜）。
2. **资源生命周期**: create 槽分配 → configure/data_sink/process 使用 → destroy 槽释放。所有 return 路径都要释放资源。
3. **Fuzzer 输入**: data_sink 槽的 API 接收 `data`/`size`；其余槽如需输入，从 `data` 切分。
4. **错误处理**: 返回指针的函数检查 NULL，返回错误码的检查非零；错误路径释放资源后 `return 0`。
5. **头文件**: 只 `#include` 实际需要的（标准库 + 目标库头文件，从候选 API 的 header 字段取）。
6. **不透明结构体**: 用工厂函数分配，不要栈分配未知大小的结构体。

请**只输出完整源代码**（在 ```{code_block} 代码块中），不要其他说明。
"""
    return prompt, lang, file_hint


