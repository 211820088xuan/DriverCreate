# driver_create 进度日志

> 约定：每次开发、调试、实验或流程排查前先读此文件；遇到问题、根因、解决方式、重要运行节点和结果须追加记录。

---

## 2026-07-29 — step2 算法改进：LLM 语义分组 + 自主序列长度

### 背景

原有两处设计问题：

1. `group_by_domain` 仅靠字符串前缀规则分组，无语义理解，对新项目命名风格适应性差。
2. `num_apis = min(8 + (driver_index % 3) * 2, ...)` 是无依据的固定公式，序列长度与领域实际规模脱钩。

### 改动内容（`step2_generate.py`）

**新增常量**
```python
MAX_APIS = 20   # API 序列硬上限
MIN_APIS = 5    # 序列下限（不足时从其他领域补）
```

**新增函数**
- `_extract_json_obj(text)` — 从 LLM 响应中健壮提取 JSON 对象（兼容 ```json 代码块和裸 `{}`）
- `classify_domains_llm(api_entries, ...)` — 用 LLM 对 API 做语义分组：先调 `deepseek-v4-flash`，失败则 `deepseek-v4-pro` 兜底；清洗结果只保留真实 API 名
- `ensure_domain_groups(project, ...)` — 封装缓存逻辑，结果写到 `intermediate/<project>/domain_groups.json`；命中缓存直接返回，不重复调用 LLM

**修改 `group_by_domain`**
- 新增 `precomputed=None` 参数
- 提供时优先用 LLM 分组；未覆盖的 API 递归走原前缀规则（不丢数据）

**重写 `design_call_sequence`**
- 参数 `num_apis=8` → `max_apis=MAX_APIS`，新增 `precomputed_groups=None`
- 序列构建逻辑改为：
  - Step 1 前置：≤3 个（`min(3, max_apis // 6)`）
  - Step 2 主领域：把 focus_domain 全部 API 纳入，受 `max_apis` 封顶；跑出 focus_domain 后最多补 3 个
  - Step 3 验证：≤2 个对偶 API（compress/decompress 等）
  - Step 4a 补充：init/cleanup 补到 `max_apis`
  - Step 4b 下限：序列 < `MIN_APIS` 时从其他领域补足

**更新调用链**
- `pre_allocate_domains`：新增 `precomputed_groups=None`，内部两处 `group_by_domain` 调用透传
- `build_prompt`：参数 `num_apis` → `max_apis`，补全 `precomputed_groups` 传递；backfill 阈值改为 `MIN_APIS`
- `generate_one_driver`：args 元组增加第 14 个元素 `precomputed_groups`；删除 `min(8 + (driver_index % 3) * 2, ...)` 计算；`build_prompt` 改传 `max_apis=MAX_APIS`
- `retry_one_failed`（闭包）：同上，删除固定公式，改传 `max_apis=MAX_APIS, precomputed_groups=precomputed_groups`
- `main()`：在 `build_signature_cache` 之后、`pre_allocate_domains` 之前调用 `ensure_domain_groups()`，结果经 `pre_allocate_domains` 和 `worker_args` 传入所有 worker

### 验证状态
- `python3 -m py_compile step2_generate.py` OK
- 尚未端到端实跑验证（待下次实验）

---

## 2026-07-31 — 代码整理：删 Anthropic 支持 + 去 emoji + 消除 hardcode

### 背景

历史遗留问题积累：Anthropic SDK 路径已弃用但未清理；prompt 字符串中混有 emoji；绝对路径 hardcode 在多处；`_VENDOR_SKIP_DIRS` 常量重复定义；Neo4j 密码明文写在源码。

### 改动内容

**`config.py`**
- 删除 `# Anthropic API` section 全部内容（`ANTHROPIC_API_KEY`、`ANTHROPIC_BASE_URL`、`ANTHROPIC_MODEL`、`ANTHROPIC_FAST_MODEL`，及注释掉的 opus 旧配置）
- `NEO4J_PASSWORD` 改为纯环境变量读取，不再有默认值
- `OSS_FUZZ_DIR`、`SH_DIR`、`PROJECTS_DIR` 改为 `os.getenv(...)` 覆盖，保留原路径作默认值
- 新增 `VENDOR_SKIP_DIRS` 常量（从 step1/step2 的重复定义提取集中）
- section 标题整理：`# Anthropic API` → `# LLM 配置`

**`step2_generate.py`**
- 删除 `try: from anthropic import Anthropic` 及 `HAS_ANTHROPIC` 变量
- 删除 `call_claude_with_model()` 函数（约 90 行）
- 简化 `call_llm()`：移除 `provider='anthropic'` 分支、`enable_thinking`、`prefill_lang` 参数，直接转发到 `call_openai_compatible_model`
- 删除 `main()` 中两处 `if LLM_PROVIDER == "anthropic": ... else: ...` 块，直接读 DeepSeek 凭证
- `_VENDOR_SKIP_DIRS` → `from config import VENDOR_SKIP_DIRS`
- prompt 字符串中 42 处 emoji 全部替换为中文标签：`⚠️`→`【注意】`、`✅`→`【可用】/【正确】`、`❌`→`【禁止】/【错误】`、`⛔`→`【严格限制】`、`📚`→`【参考代码】`、`🚫`→`【禁止】`（`print()` 中的 emoji 保留，不影响 LLM 输入）

**`step1_prepare.py`**
- `from config import` 增加 `VENDOR_SKIP_DIRS`，删除本地 `_VENDOR_SKIP_DIRS` 定义
- `query_project_graph()` 入口增加 `NEO4J_PASSWORD` 非空检查，未设则跳过图谱查询而非崩溃

**`build_delivery.py`**
- `ROOT = Path("/root/gyx/driver_create")` → `ROOT = Path(__file__).parent.resolve()`

### 新增文件
- `.env.example`：列出所有需要设置的环境变量（`NEO4J_PASSWORD`、`DEEPSEEK_API_KEY` 等）

### 验证状态
- `python3 -m py_compile` 全部 13 个模块通过（config + 6 个顶层 + agent/6 个）
- 尚未端到端实跑验证（下次跑实验时补充）

### 未做（后续再议）
- `step2_generate.py` 拆模块（3100 行 → `step2/` 子目录）
- library 元数据（zlib/libxml2 等）集中到 `library_registry.json`

---

## 2026-08-05 — build_prompt_from_plan 重构：三模式「基础段 + 差异化段」

### 背景

重构指导要求三模式（focus/peer/cross）从「API 前缀分组 + LLM 设计序列」转向「骨架驱动」。前期已完成 plan_gen/skeleton_mine/role_annotate 等数据准备，build_prompt_from_plan 也已写成旧 prompt 的信息超集。但三模式的 prompt 内容侧重点不清晰：peer 塞了同场景完整范例（语料污染风险）、cross 缺差异化信息（骨架来源/适配指引/角色标签全无）、focus 缺未测 API 位置提示。

用户洞察：三模式应是「基础质量段（都给）+ 差异化侧重段（引导方向不同）」结构，而非各自不同。

### 改动内容（`step2_generate.py`）

**新增两个 helper（约 line 1232）**
- `load_project_role_distribution(project)` — 从 `_shared/role_labels.jsonl` 聚合本项目 API 角色分布 `{role: [api...]}`
- `load_skeleton_source_info(skeleton_id)` — 从 `_shared/skeletons.json` 取骨架来源信息（序列/支持 driver 数/来源项目/场景分布/置信度/slot_multiplicity）

**usage_section 重构（基础段，三模式统一）**
- 三模式都给「本项目已验证 driver 完整范例」（基础质量，帮 LLM 理解本项目 API 调用范式 + 正确 #include）
- 三模式都给「候选 API 的正确用法」per-API snippets（真实调用片段，非模板）
- 去掉 peer 的「同场景标杆项目完整范例」（语料污染风险）
- 去掉 cross 的「不给完整范例」限制（§7.2 防的是跨场景范例，本项目范例是安全的）

**mode_section 差异化段（按模式注入）**
- `focus`：「未测 API 插入指引」——插入理由（plan evidence.why）+ 本项目 API 角色分布
- `peer`：「同场景项目 API 组织方式参考」——同场景标杆项目列表 + 本项目 API 角色分布 + 空 slot 提示
- `cross`：「跨场景骨架迁移指引」——骨架来源（序列/支持数/来源项目/场景/置信度）+ 跨场景适配指引（语义对齐：process slot 在压缩库→压缩 API 等）+ 本项目 API 角色标签分布 + 空 slot 提示

**lang_guide 重写（详细约束）**
- C/C++ 各 8 条约束（入口函数/不透明结构体/参数严格匹配/goto 安全/输入处理/禁内部头/返回值检查/资源释放）
- 去掉项目特定示例（FLAC 等），保留通用约束

**prompt 拼装**
- 去掉 peer_info crash 统计段（crash 暂不管）
- 项目背景保留同场景标杆项目列表（无 crash 数字）
- prompt 拼装顺序：lang_guide → 项目背景 → build_info → header_info → fuzzing_headers → header_map → constants → version → template → 骨架序列 → usage_section（基础）→ mode_section（差异化）→ 生成要求

### 已知弱项（待后续开发）
- `plan_gen.py` slot 填充只靠签名规则，召回 ~19%，多数 slot 空——LLM fallback（空 slot 时让 LLM 从本项目 API 选）未实现
- `role_labels.jsonl` 里 c-blosc2 仅 13 个 API 被标注（scored.json 有 163 个），覆盖率低——后续可补标注

### 验证状态
- `python3 -m py_compile` OK
- 三模式 prompt 结构验证通过：focus ~7.7k / peer ~8.7k / cross ~16.4k chars
- 后台 peer run（PID 2541169）用新 prompt 跑 c-blosc2 peer 3 driver 验证中

### 下一步
- 等 peer run 结果验证新 prompt 实际生成质量（旧 prompt 因 L1 include 违规生成 0 个）
- 若质量 OK，跑 c-blosc2 三模式 end-to-end（Phase 10）
- plan_gen LLM fallback 开发（提升 slot 召回）

---

## 2026-08-05（续）— role_labels 集成 + focus 统一 + header 内部路径修复

### role_labels 集成到 plan_gen（`tools/plan_gen.py`）

**问题**：`_fill_slot_candidates` 只用签名规则筛（`_sig_rule_role`），召回 ~19%，cross 模式 7 个 slot 因 no_candidate 跳过。

**改动**：
- 新增 `_load_role_labels(project)` — 从 `_shared/role_labels.jsonl` 加载本项目 {api: role} 映射
- `_fill_slot_candidates` 改为两轮筛：第一轮签名规则（高精度），第二轮 role_labels 标签（LLM 语义标注补召回）
- `_gen_peer_cross_plan` + `_gen_focus_plan` 加载 role_labels 并透传

**效果**：c-blosc2 三模式 slot 候选 confidence 分布：
- focus: 5 driver, 20 signature
- peer: 5 driver, 72 signature + 7 role_label
- cross: 5 driver, 103 signature + 10 role_label, **7 skipped → 0**

### focus 统一走 plan 流程（`step2_generate.py`）

**问题**：focus 走旧 `_run_focus_mode`（design_call_sequence + build_prompt + L2/L3 降级），peer/cross 走新 `_run_peer_cross_mode`（plan 驱动 + L2/L3 拦截），代码路径分裂。

**改动**：
- `main()` 删掉 focus/else 分支，三模式统一调 `_run_peer_cross_mode(project, mode, ...)`
- `_run_peer_cross_mode` docstring 更新为「focus/peer/cross 通用」
- `_run_focus_mode` / `generate_one_driver` / `build_prompt` / `design_call_sequence` / `ensure_domain_groups` / `pre_allocate_domains` 成死代码（待清理，无外部引用）

### header 内部路径修复（`step2_generate.py`）— 关键 bug

**问题**：peer run 生成 0 个 driver，L1 include 违规（`blosc/frame.h`）。根因：
1. `build_header_api_map` 扫源码树所有 .h，含内部路径 `blosc/frame.h`，LLM 照抄 header_map
2. `header_info`（主要头文件列表）全是 `blosc/*.h` 内部路径，LLM 照抄

**改动**：
- `build_header_api_map`：优先扫 `include/` 子目录，跳过 `blosc/`/`plugins/`/`internal/` 内部路径，返回去掉 `include/` 前缀的路径
- `header_info`（build_prompt_from_plan）：只保留 `include/` 下或顶层 .h，跳过内部子目录，去掉 `include/` 前缀

**效果**：c-blosc2 header_map 现在返回 `blosc2.h`/`b2nd.h`/`blosc2/blosc2-stdio.h`（公开），`frame_new`/`register_tuner_private` 等内部路径 API 不再给出 header（LLM 改用主公开头 `blosc2.h`）

### 验证状态
- `python3 -m py_compile` OK
- 三模式 prompt 结构验证通过
- 后台 peer run（PID 2543120）用修复后版本跑 c-blosc2 peer 3 driver 验证中（等 LLM 响应 ~5min/driver）

---

## 2026-08-05（续）— tools/ 目录按功能分子目录

### 背景

tools/ 下 9 个文件扁平堆放，功能混杂（KG 操作 / Phase 数据准备 / 覆盖率 / 清理），看着乱。

### 改动

**重组结构**：
```
tools/
├── kg/                      # KG 操作
│   ├── add_call_order.py    # 给 KG CALLS 边补 order/order_last
│   ├── export_role_dataset.py # 导出 role 标注数据集 + 体检报告
│   └── kg_gap_query.py      # 只读查询 API 缺口
├── phase/                   # Phase 5/6 数据准备
│   ├── role_annotate.py     # Phase 5: LLM 标注 API 角色
│   ├── skeleton_mine.py     # Phase 6: 挖骨架序列
│   └── plan_gen.py          # Phase 6b: 三模式 plan 生成
├── analyze_fuzzing_headers.py  # 头文件白名单（pipeline 调用）
├── aggregate_coverage.py    # 覆盖率去重并集统计
└── clear.sh                 # 项目清理
```

**sys.path 修正**：`tools/kg/*.py` 和 `tools/step2_tools/*.py` 的 `sys.path.insert` 从 `parent.parent` 改为 `parent.parent.parent`（多一层）。

**未移动的**：
- `analyze_fuzzing_headers.py` 留 tools/ 根（被 run_pipeline.py 以 `tools/analyze_fuzzing_headers.py` 路径调用，移动要改 run_pipeline）
- `aggregate_coverage.py` / `clear.sh` 留 tools/ 根（独立工具）

### 验证
- 8 个 .py 全部 `ast.parse` 通过
- `plan_gen` 模块 import 链验证 OK（config / plan_loader / skeleton_loader 都能 import）
- step2 后台进程（PID 2545147）未受影响
- README.md 目录树已更新

### 后续
- step2_generate.py 3576 行待拆模块（独立 todo，先清死代码再拆）

### 二次重组：按 step 分布

用户要求按 step 归类，二次重组：

```
tools/
├── step1_tools/          # step1 前置：KG 数据富化与检查
│   ├── add_call_order.py
│   └── kg_gap_query.py
├── step2_tools/          # step2 前置：生成 driver 的数据准备
│   ├── analyze_fuzzing_headers.py  # 从 tools/ 根移入（改 run_pipeline 调用路径）
│   ├── export_role_dataset.py      # 从 tools/kg/ 移入
│   ├── role_annotate.py
│   ├── skeleton_mine.py
│   └── plan_gen.py
├── coverage_tools/       # fuzz 后覆盖率统计
│   └── aggregate_coverage.py
└── clear.sh              # 通用清理
```

**改动**：
- `tools/kg/` 拆分消失：add_call_order + kg_gap_query → step1_tools/，export_role_dataset → step2_tools/
- `analyze_fuzzing_headers.py` 从 tools/ 根移到 step2_tools/（sys.path 改 parent.parent.parent，run_pipeline.py 调用路径改 `tools/step2_tools/analyze_fuzzing_headers.py`）
- `aggregate_coverage.py` 移到 coverage_tools/（不 import config，不用改 sys.path）

**验证**：8 个 .py 编译通过，run_pipeline 编译通过，sys.path 全部一致（parent.parent.parent，aggregate_coverage 除外不 import config）

### 用户离线，自主验证模式启动

用户告知接下来无法交流，要求：验证暴露问题后自动针对问题修，跑完 step2 → step3 build → 针对暴露问题修 P1 #4-8 等，全程记录到 log.md。

**当前验证批次**（PID 2550893）：step2 --mode=all 3（focus+peer+cross 各 3 driver），用最新代码（L2 警告 + header 修复 + role_labels 集成 + 死代码清理后 2079 行）。

### 验证暴露问题 #1：file_hint 同名覆盖

**现象**：focus 模式 3 个 driver 都保存为 `blosc2_schunk_new_focus_crfuzzer.c`（互相覆盖，最终只保留 1 个）。

**根因**：`build_prompt_from_plan` 的 `file_hint` 用 plan driver 第一个候选 API 名，focus 三个 driver 的 base shape 相同（focus_own），第一个 slot 候选都是 `blosc2_schunk_new`，导致 file_hint 相同。

**修法（待全跑完执行）**：file_hint 加 driver_id/index 后缀区分，如 `blosc2_schunk_new_focus#1_crfuzzer.c` 或 `{first_cand}_{mode}_{idx}_crfuzzer.{ext}`。

### 验证暴露问题 #1 已修：file_hint 加 driver_id 后缀

**改动**（step2_generate.py build_prompt_from_plan）：file_hint 从 `{first_cand}_{mode}_crfuzzer.{ext}` 改为 `{first_cand}_{mode}_crfuzzer_{id_suffix}.{ext}`，id_suffix 取 plan_driver["id"] 的 # 后数字。

**验证**：focus#1/2/3 现在生成 `blosc2_schunk_new_focus_crfuzzer_1/2/3.c`，不再同名覆盖。peer/cross 的 driver_id 也不同，加后缀不影响（只防同名）。

**重跑**：focus 3 driver 后台重跑（PID 2551829），peer/cross 已 OK 保留。

### 验证暴露问题 #2：LLM 传参数数量不对（编译失败根因）

**现象**：focus 3 driver 编译全失败（round 1/3 built=0 failed=3）：
- `blosc2_schunk_new_2_focus_crfuzzer.c:62: error: too few arguments to function call, expected 9, have 5`
- `blosc2_schunk_new_3_focus_crfuzzer.c:27: error: too few arguments, expected 9, have 3`
- `blosc2_schunk_new_3_focus_crfuzzer.c:37: error: too many arguments, expected 4, have 8`
- 还有 incompatible pointer types（b2nd_array_t ** vs b2nd_context_t *）

**根因**：LLM 调用 API 时参数数量/类型不匹配 signature。L2 警告没拦住——API 名对（在 scored.json），只是参数传错。

**修复方向**：
1. prompt 强化：sequence_section 里每个候选 API 标注参数数量 + 强调"从 signature 读取参数数量"
2. 加参数数量校验（L5）：生成后检查 API 调用参数数 vs signature

**修复循环效果**：round 1 build_fix 未正常提交（max_steps），code 修复 0/2（未能修复）。等 round 2/3 看。

### 验证暴露问题 #3：容器缺 dev 包 .so（链接库找不到）

**现象**：round 1 全失败 `cannot find -llz4 -lzstd -lz`。容器只有 `/usr/lib/x86_64-linux-gnu/liblz4.so.1`（运行时），缺 `liblz4.so`（开发包）。cmake 构建走 target_link_libraries（知道 .so.1），agent 注入的 clang -lxxx 需要 .so。

**修复**（agent/agent_main.py）：新增 `_SO_SYMLINK_GUARD`，在 `write_buildsh_driver_loop` 注入编译循环前创建 `.so → .so.1` 符号链接（lz4/zstd/z/lzma/bz2/snappy，覆盖 x86_64/aarch64 常见路径）。

**效果**：round 1 built=0→2，focus#1 + focus#3 直接编译成功，focus#2 agent_repair 修复 1/1（b2nd_array_t 栈分配问题）。

### focus 验证结果：3/3 编译成功（2 轮）

- round 1: built=2 failed=1（focus#2 b2nd_array_t 栈分配，agent_repair 修 1/1）
- round 2: built=3 failed=0（全部通过）

重构全部生效：L2 警告 + file_hint 去重 + 参数数量提示 + .so 符号链接 guard + agent_repair 修复。

### peer 验证结果：2/3 编译成功（3 轮）

- round 1: built=2 failed=1（b2nd_free_ctx_2_peer_crfuzzer，agent_repair 0/1 未修好）
- round 3: built=2 failed=0... 实际最终 2/3（b2nd_free_ctx 始终失败）

累计：focus 3/3 + peer 2/3 = 5/6。

### cross 验证结果：3/3 编译成功（3 轮）

- round 1-2: built=2 failed=1（blosc2_decompress_ctx_2，agent_repair 修中）
- round 3: built=3 failed=0（全部通过）

## 最终端到端验证结果

| 模式 | 生成 | 编译成功 | 备注 |
|---|---|---|---|
| focus | 3 | 3/3 | round 2 全过（agent_repair 修 b2nd 栈分配） |
| peer | 3 | 2/3 | b2nd_free_ctx_2 未修好（agent_repair 0/1） |
| cross | 3 | 3/3 | round 3 全过 |
| **合计** | **9** | **8/9 (89%)** | |

对比重构前：0/9（L2 硬拦 + 链接库找不到 + 参数数量错）。

**重构全部生效**：
1. L2 警告（不硬拦合法 driver，build 兜底）
2. file_hint 加 driver_id 后缀（防同名覆盖）
3. sequence_section 参数数量提示 + 严格约束（不再 too few/many arguments）
4. role_labels 集成 plan_gen（slot 召回提升）
5. header_info/header_map 修复（过滤内部路径）
6. .so 符号链接 guard（解决容器缺 dev 包）
7. agent_repair 正常修复（focus b2nd 栈分配、cross decompress_ctx）

### 最终 per-target 结果

| 模式 | target | 状态 | 修复路径 |
|---|---|---|---|
| focus | blosc2_schunk_new_1 | ok | 直接成功 |
| focus | blosc2_schunk_new_2 | ok | agent_repair code 修复后成功 |
| focus | blosc2_schunk_new_3 | ok | 直接成功 |
| peer | b2nd_free_ctx_2 | **failed** | agent_repair code 修复失败 |
| peer | blosc2_create_cctx_3 | ok | 直接成功 |
| peer | blosc2_stdio_mmap_write_1 | ok | 直接成功 |
| cross | blosc2_create_cctx_1 | ok | 直接成功 |
| cross | blosc2_decompress_ctx_2 | ok | agent_repair code 修复后成功 |
| cross | blosc2_stdio_write_3 | ok | 直接成功 |

**8/9 编译成功（89%）**：5 直接成功 + 3 agent_repair 修复成功 + 1 失败（peer b2nd_free_ctx_2，待后续查）。

### 自主验证阶段完成

用户离线期间自动完成：step2 三模式生成 → step3 build → 针对暴露问题修（file_hint/L2/参数数量/.so guard）→ 最终 8/9 成功。剩余 peer b2nd_free_ctx_2 失败属 P1 范畴，待查具体错误。

---

## 2026-08-06 — output 结构重构 + get_oss_fuzzer.sh 搬入项目

### 背景

用户要求：output 重构为 driver + oss-bin 两个子目录；get_oss_fuzzer.sh 从 oss-fuzz 搬到 driver_create，减少散乱依赖。

### 改动

**1. output 结构重构**（`config.py` + `agent/agent_main.py`）
- `output_for(project, mode)` 路径改：`output/<project>/<mode>/` → `output/<project>/driver/<mode>/`
- 新增 `oss_bin_for(project, mode)` → `output/<project>/oss-bin/<mode>/`
- `actual_binaries` / `_backup_and_clean_oss_bin` / `replay_via_get_oss_fuzzer` 改用 `oss_bin_for`
- 删常量 `EXTRACT_DIR_ROOT`（改用 `oss_bin_for` 函数）
- `_backup_and_clean_oss_bin` 加 mode 参数
- `agent_main_build` 加 mode 参数，透传给脚本 + backup_clean
- step3_build / agent_build_fix / agent_main 的 `agent_main_build` 调用都传 mode

**2. get_oss_fuzzer.sh 搬入项目**（`scripts/get_oss_fuzzer.sh`）
- 从 `oss-fuzz/get_oss_fuzzer.sh` 搬到 `driver_create/scripts/get_oss_fuzzer.sh`
- `OSS_FUZZ_HOME` 改读环境变量 `OSS_FUZZ_DIR`（默认 `/root/gyx/oss-fuzz`）
- 新增第 3 参 `mode`：控制 `EXTRACT_DIR` = `artifacts/output/<project>/oss-bin/[<mode>/]`
- `LOGS_DIR` 改到 `artifacts/logs/`
- `GET_OSS_FUZZER_SH` 常量改指 `DRIVER_CREATE_DIR / "scripts" / "get_oss_fuzzer.sh"`

**3. clear.sh 跟随改**
- `--keep-output`：保留 `output/<p>/driver/`（源码），删 `output/<p>/oss-bin/`（二进制）
- 兼容清理旧路径 `oss-fuzz/oss-bin/<p>/` + `oss-fuzz/logs/<p>.log` 残留
- 新增清理 `artifacts/logs/<p>.log`

**4. 数据迁移**
- `output/c-blosc2/{focus,peer,cross}/*.c` → `output/c-blosc2/driver/{focus,peer,cross}/`

### 验证
- 全模块 `py_compile` 通过
- `output_for` / `oss_bin_for` 路径正确
- `collect_driver_sources` 从新路径读到 3 个 focus driver
- README 目录树 + step3 docstring 已更新

### 路径验证结果（step3 --no-repair focus）

- driver 从 `output/c-blosc2/driver/focus/` 读到 3 个 ✓
- 脚本从 `scripts/get_oss_fuzzer.sh` 跑，传 `mode=focus` ✓
- log 在 `artifacts/logs/c-blosc2.log` ✓
- 0/3（--no-repair 不注入编译循环，只编项目自带，预期）
- oss-bin 新路径 `output/c-blosc2/oss-bin/focus/` 待完整修复循环生成

**重构完成**：output 分 driver/ + oss-bin/，get_oss_fuzzer.sh 搬入 scripts/，项目对 oss-fuzz 的散乱依赖收敛到单环境变量 `OSS_FUZZ_DIR`。

---

## 2026-08-06（续）— P1 #4 #5 修复

### P1 #4：DC_OFFICIAL_RC 无人读 → 加 read_dc_official_rc + round 循环判断

**问题**：get_oss_fuzzer.sh 保存 `DC_OFFICIAL_RC=$?`（官方构建退出码）但 agent 无人读。官方构建失败（缺库/环境）时所有 driver 报缺库，修复循环空耗三轮。

**改动**（`agent/agent_main.py` + `agent/agent_pipeline.py`）：
- 新增 `read_dc_official_rc(log_path)` — 从 log grep `official build exit code: N`，返回退出码
- `run_repair_pipeline` round 循环：build 后读 DC_OFFICIAL_RC，若 != 0 且 round>=1 仍全失败 → 打 warning + break（项目环境问题，agent 修不好）

### P1 #5：extract_target_error_lines in_scope 永不复位 → 遇 Building 切换

**问题**：`agent_triage.extract_target_error_lines` 的 `in_scope` 一旦 True 永不复位，target A 出现后整个 log 的 error 行都算 A 的，分诊误归。

**改动**（`agent/agent_triage.py`）：遇 `Building XXX` 行切换 scope——含当前 target 则进入，否则退出。验证：模拟 log 里 targetA 只收集自己的 error，不含 targetB 的。

### P1 剩余（优先级低，延后）
- #6 dependencies 硬编码：无下游消费，修了数据完整但功能无提升
- #7 Q7 scope 错：改了要重跑 step1 重生成 scored.json
- #8 无范例 fallback：c-blosc2 有范例不受影响；修法待重新定（不给同场景完整范例，可给 per-API snippets）

---

## 2026-08-06（续）— P2 #9 #10 #11 #12 修复

### P2 #9：编译修复不自验 → submit_fix 加 bash -n 语法检查 + 回滚

**问题**：build_fix 改完 build.sh 不验证就进 code_fix，build.sh 改坏则所有 replay 失败。

**改动**（`agent/agent_build_fix.py`）：`submit_fix` handler 提交前跑 `bash -n build.sh` 语法检查，语法错则回滚 .dcbak 拒提交。

### P2 #10：replay 成本无全局上限 → 加 DC_GLOBAL_BUILD_BUDGET

**问题**：可达 90 次 docker 构建（N driver × 3 步 × 3 轮）。

**改动**（`config.py` + `agent/agent_main.py` + `agent/agent_pipeline.py`）：
- `config.py` 新增 `DC_GLOBAL_BUILD_BUDGET=30`（环境变量可调）
- `agent_main.py` 模块级 `_GLOBAL_BUILD_COUNT` + `global_build_count()`，`agent_main_build` 递增
- `agent_pipeline.py` round 循环每轮检查，达上限则 break

### P2 #11：日志被 replay 冲掉 → 保留 .prev

**问题**：`: > $OUTPUT_LOG` 每次 replay 清空，pipeline 结束后日志是最后一次单 driver replay 的。

**改动**（`scripts/get_oss_fuzzer.sh`）：清空前 mv 旧 log 到 `<project>.log.prev`，保留上一次完整 log。

### P2 #12：.dcbak 第二次被污染 → overwrite=False

**问题**：`session_backup_injectables` 用 `overwrite=True` 无条件覆盖，第二次运行用含注入块的 build.sh 覆盖原始 .dcbak，原始永久丢失。

**改动**（`agent/agent_main.py`）：`session_backup_injectables` 改 `overwrite=False`，仅首次创建 .dcbak，保留原始快照。

---

## 2026-08-06（续）— 补 fuzz runner 脚本，pipeline 闭环

### 背景

pipeline 到 step3 build（产出 oss-bin 二进制）就停了，缺 fuzz 阶段（跑二进制发现 crash）。用户"以量取胜"策略要 fuzz 过滤闭环。

### 新增 `scripts/fuzz_runner.py`

OSS-Fuzz 二进制要在 base-runner 容器跑（host glibc 不够，实测 `GLIBC_2.38 not found`）。

**流程**：
1. 找 `oss-bin/<project>/[<mode>/]` 下 `*_crfuzzer` 二进制
2. 为每个二进制解压 `seed_corpus.zip`（`oss-fuzz/build/out/<project>/`）作种子
3. `docker run base-runner` 挂载 oss-bin + corpus + crash 目录，跑 `./binary /corpus -max_total_time=N -artifact_prefix=/crashes/`
4. crash 收集到 `artifacts/output/<project>/crashes/<mode>/`
5. 输出 `fuzz_summary.json`（每 fuzzer 的 crash 数 + 耗时 + tail）

**参数**：`<project> [--mode=<m>] [--max-time=300] [--workers=2]`

### pipeline 闭环

```
step1 情报 → step2 生成 → step3 build（oss-bin 二进制）→ fuzz_runner（crash）→ aggregate_coverage（覆盖率统计）
```

### 验证状态
- 编译 OK，base-runner 镜像在
- 当前 oss-bin 空（需先跑完整 step3 build 生成二进制才能跑 fuzz）

---

## 2026-08-06 — 验证实验：fuzz_runner 闭环验证 + .bak 堆积修复

### .bak 堆积 bug 修复

**问题**：`_backup_and_clean_oss_bin` 每次备份旧 oss-bin 到 `.bak.时间戳`，从不清理 → output/c-blosc2 下堆积多个 80-100M 的 .bak 目录。

**修复**（`agent/agent_main.py`）：备份前先 glob 删除同目录下所有旧 `.bak.*`，只留最近一次。

### step3 focus 重跑结果

**1/3 编译成功**（blosc2_schunk_new_3）。比上次（3/3）差，原因：agent_repair 的 compile_driver（DC_ONLY 单编）说"ok=true 无需修改"，但全量编 diff built=0——DC_ONLY 单编成功但全量编失败（可能 driver 源码被 compile_driver 写回时改坏，或全量编链接冲突）。属 P1/P2 范畴待查。

### fuzz_runner 闭环验证 ✓

- step3 产出 1 个二进制 → oss-bin/focus/
- `fuzz_runner.py c-blosc2 --mode=focus --max-time=60` 跑通
- docker run base-runner 跑 libFuzzer 20.8s，0 crash（c-blosc2 压缩 API 60s 不易崩，正常）
- summary → output/c-blosc2/fuzz_summary.json

**pipeline 闭环验证成功**：step1 → step2 → step3 build → fuzz_runner → summary。

### 验证暴露问题 #4：DC_ONLY 单编清空整个 oss-bin 导致前一个修好的被删

**现象**：step3 focus 从之前 3/3 退化到 1/3。log 显示 DC_ONLY 单编 #1 #2 都 Successfully built + 已提取，但最终 oss-bin/focus/ 只有 #3。

**根因**：`_backup_and_clean_oss_bin` 每次 build 前清空**整个** oss-bin/<mode>/。DC_ONLY 单编逐个修复时，编 #2 前清了 #1，编 #3 前清了 #2，最后只剩 #3。

**修复**（`agent/agent_main.py`）：`_backup_and_clean_oss_bin` 加 `dc_only` 参数——
- dc_only 非空（单编修复）：只删目标二进制，保留其他已修好的
- dc_only 为空（全量编）：备份整个 + 清空（原逻辑）
`agent_main_build` 透传 dc_only。

---

## 2026-08-06（续）— 数据污染治理：任务 1/3/4

### 任务 1：get_oss_fuzzer.sh 清理陈旧产物

**问题**：脚本侧只有 mkdir -p 无 rm -rf，旧二进制残留被当本轮成功（轮次内掩盖错误、replay 恒成功、跨次拿旧二进制去 fuzz）。

**修复**（`scripts/get_oss_fuzzer.sh`）：build_image 前加 `rm -rf "$EXTRACT_DIR"/*` + `rm -rf build/out/$PROJECT`。只清当前 mode 子目录，不连累别的模式。dry check 清理生效。

### 任务 3：_find_complete_driver_examples 归属校验 + 改排序

**问题**：按文件大小升序取最小 2 个（优先挑中 standalone runner / fuzz_main.c 等小污染文件），无归属校验。

**修复**（`step2_generate.py`）：
- 排序改按本项目 API 调用数降序（非文件大小升序）
- 加归属校验：提取文件调用的函数名，与 scored.json API 池求交，先剔 libc 黑名单（_STDLIB_C + main），交集 ≥3 或 ≥50% 才采用
- 不达标丢弃 + 打日志，全不达标不给范例

**验证**：c-blosc2 选出 fuzz_compress_frame.c + fuzz_compress_chunk.c（真实 driver，非小污染文件）。

### 任务 4：删 _sig_rule_role 的 name 关键词

**问题**：5 处 `if kw in name`（free/destroy/create/new/alloc/open/get/read/next/iter 等）按 API 名判角色，get/read/next 大量命中 query 类，误判 process 污染骨架形状。

**修复**（`tools/step2_tools/plan_gen.py`）：删全部 name 关键词，只看签名形状（create=返回指针+参数少 / data_sink=首参 const void*+size / configure=首参 handle 指针+返回 int/void）。destroy/process/query 留给 LLM。

**验证**：name 关键词 0 处。签名规则召回降（peer 0→23 skipped, cross 5→1 driver）——预期，为任务 2 LLM 填槽让路。

### 任务 2：plan_gen LLM 填槽（签名规则低召回的兜底）

**问题**：签名规则实测召回 19%，删 name 关键词后更低（peer 23 skipped, cross 103 skipped/1 driver）。81% 槽填不上 → 闸门 2 不过。

**修复**（`tools/step2_tools/plan_gen.py`）：
- 新增 `_llm_fill_missing_roles(project, scored_apis, role_labels)`：对 role_labels 未覆盖的 API 批量调 LLM 标注
- 复用 role_annotate 的 `_annotate_batch`（分批 40 + 完整性校验：发 N 收 N，缺补 unknown）+ fast/strong 两级模型兜底
- 缓存 key = hash(name + signature + description)（跨项目同名不串台）
- 结果追加到 role_labels.jsonl（_load_role_labels 下次读到，第二次不重调 LLM）
- _gen_focus_plan / _gen_peer_cross_plan 加载 role_labels 后调 _llm_fill_missing_roles

**关键 bug 修复**：_append_cache 写 role_labels_cache.jsonl，但 _load_role_labels 读 role_labels.jsonl——两者不同步，导致第二次仍报"148 未标注"。改 _llm_fill_missing_roles 直接追加到 role_labels.jsonl。

**验证**：c-blosc2 role_labels 15→163（全覆盖）。peer 23 skipped→0（5 driver），cross 103 skipped/1 driver→0 skipped（5 driver）。

### 任务 5：run_pipeline 接 skeleton_mine + plan_gen

**问题**：line 180-181 是 [Phase 6 TODO] 注释，没实际调用。step2/step3 也没传 --mode 跑三模式。

**修复**（`run_pipeline.py`）：
- skeleton_mine：skeletons.json 不存在才跑（全局一次），已存在跳过
- plan_gen：每项目跑一次（内部三模式），传 --num-drivers（上限不是目标）
- step2_generate：for m in modes 跑三模式
- step3_build：for m in modes 顺序跑（共享 build.sh 不能并行），传 --mode + --max-rounds

**验证**：编译 OK，ast 解析确认 run() 顺序：step1→analyze_fuzzing_headers→skeleton_mine→plan_gen→step2(三模式)→step3(三模式)。

### 任务 6：覆盖率聚合改四组 + union-vs-k 曲线（框架完成）

**修复**（`tools/coverage_tools/aggregate_coverage.py` 重写）：
- 四组：origin/focus/peer/cross（原 new/origin 二分组）
- 主指标：union-vs-k 曲线（每组随机抽 k 个求覆盖并集，SAMPLE_TIMES=20 次取均值±标准差，k=1..N）
- 对比点：k = min(有数据的组 N) - 1（min(N) 处产出最少那组只有单次实现无法平均）
- 副指标：各组满 N 的 full_union_lines（显式标 N）
- 0 driver 的组用 n/a，不用空白或 0

**run_cov_experiment.sh 壳**（`scripts/run_cov_experiment.sh`）：
- 覆盖率 sanitizer 构建链路 + 四组跑 libFuzzer 收集 .cov.json 框架
- TODO：step3_build.py 要加 --sanitizer=coverage 支持（当前硬编码 address）；fuzz_runner.py 要加 --coverage 选项产 .cov.json（调 llvm-profdata merge + llvm-cov export）；完整实现需真实 coverage 数据验证

## 2026-08-06 Gate 2 通过（按需标模式）

### 流程
1. skeleton_mine 重挖骨架（186→150，relabel 后 data_sink 收紧）
2. plan_gen 改按需标：删开头预标 _llm_fill_missing_roles，改 _fill_slot_candidates 第三轮（槽位填不够时一批批标，边标边筛）
3. llm_fill_concurrent.py 并发 6 跑 24 项目 plan_gen

### bug 修复
- plan_gen.py:46 `if not role_labels: return` → `if not scored_apis`（0 覆盖项目不调 LLM 的 bug，导致 cross 全 no_candidate）

### Gate 2 结果（过）
- cross 平均/项目: 4.29 (≥3 ✅)
- cross ≥3 项目数: 21/24 (≥6 ✅)
- role_labels.jsonl: 9862 条

### 24 项目明细
- cross 满产 5 driver: 18 项目
- cross 4 driver: libspng(108 skip), sql-parser(134 skip)
- cross 0 driver: freetype2(scored 32 API 全错非 FT_*), lua(0 API), md4c(4 API 太少)

### 发现的问题
- 按需标方案 A 对 0 driver 边大项目退化成全标（capstone 1958/2000, mongoose 全标）——槽位填不够时一直标下一批
- freetype2 scored.json 的 32 API 全错（harfbuzz/C++ 类，非 FT_*）——step1 Neo4j 查询捞错，未修
- focus 0/1 多数（0 driver 边项目 focus 不可用，符合 §7.1 设计 own_shapes 空）

### 下一步
Gate 2 过，可进第 9 步全量实验（step2 生成 + step3 构建 + fuzz_runner）

### 混合方案验证（通过）
改成：create/configure/data_sink 签名规则全 all_apis 筛（不受 N 限制）+ process/destroy/query 开头并发预标 scored top N=200 里签名规则没命中的。

新增 `_llm_fill_top_n`（并发批量标 top N）+ 删 `_fill_slot_candidates` 第三轮（按需标）。

Gate 2 保持：cross 平均 4.29，≥3 项目 21/24。
标注量可控：libcoap 20 / mbedtls 104 / ndpi 46 / zstd 36（对比方案 A 的 capstone 1958 / mongoose 2000 全标）。
role_labels.jsonl: 10236 条。

## 2026-08-06 阶段 2 数据问题排查（freetype2/lua/md4c）

### 根因（图谱数据问题，非 step1 bug）
- freetype2: Neo4j 里 freetype2 HAS_API 连了 31 个 freestack/coretext API（错），真 FT_* API 错归到 kcodecs/cairo。图谱建模错误。
- lua: HAS_API=0（图谱漏建 lua API 边）。driver 调 strcmp/_exit（C 标准库）。图谱漏建。
- md4c: HAS_API=4（md_parse/md_html 等真 API，正确）。数据稀疏非错，但 4 API 填不上骨架。

### 决策
- 图谱数据问题需修图谱构建（另一个项目），非本仓库范围。
- 阶段 3 选 4-6 项目时避开 freetype2/lua/md4c。
- md4c 保留（数据真，但 cross 产不出）。

## 2026-08-06 阶段 1 step3 验证（c-blosc2 focus）

### 修的 bug
1. Docker 代理 502：~/.docker/config.json 的 proxies(127.0.0.1:7890) 在容器内指向容器自己。删 proxies 配置 + get_oss_fuzzer.sh unset 代理 + 容器 --network=host 直连 archive.ubuntu.com（200）。
2. agent_main_build mode 传参：dc_only 为空时 mode 传到 $2（被当 dc_only）。加空占位 `cmd.append("")`。
3. agent_pipeline line 248 build_fn(project) 没传 mode：改成 build_fn(project, mode=mode)。
4. get_oss_fuzzer.sh dc_only 清空：dc_only 时只删 target，不清整个 EXTRACT_DIR。

### step3 --no-repair --mode=focus 结果
- 整批 build 7/8 成功（88%）
- oss-bin/focus/ 有 7 个二进制 ✅
- 唯一失败：blosc2_schunk_from_buffer_2_focus_crfuzzer（LLM 生成的 driver 源码问题）

### 遗留 bug
- run_repair 模式（默认，进修复循环）：整批 build 后进 dc_only 修复，oss-bin/focus 被清空。--no-repair 模式不受影响。需查 dc_only 修复的清空逻辑。

### 阶段 1 分步验证完成（c-blosc2 三模式）
**step2 生成**：focus 8 / peer 8 / cross 8 = 24 driver
**step3 构建**（--no-repair）：focus 7/8 (88%) / peer 6/8 (75%) / cross 6/8 (75%) = 19/24 (79%)
**fuzz_runner**（ubuntu-24-04 runner + LD_LIBRARY_PATH）：focus 16 crashes / peer 6 / cross 12

### 修的 bug（阶段 1）
5. get_oss_fuzzer.sh Dockerfile+build.sh glob 写死上一模式：--no-repair 不调 inject，mode 切换时 glob 不更新。build_and_report 加 restage 后更新 build.sh + Dockerfile 的 glob 为当前 mode。
6. fuzz_runner base-runner glibc 2.31 不匹配构建镜像 ubuntu-24.04 glibc 2.39：改用 base-runner:ubuntu-24-04。
7. fuzz_runner 没设 LD_LIBRARY_PATH：加 -e LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu（但 ubuntu-24-04 runner 自带，非必需）。

### 阶段 1 run_repair 验证（mode 传参修复后）
step3_build.py c-blosc2 --mode=focus --max-rounds=1：7/8 编译成功（1 轮），oss-bin/focus 有 7 个二进制。
mode 传参修复（build_fn(project, mode=mode)）后，run_repair 清空 bug 也解决（diff built=7 非 0）。

### 阶段 1 一键 pipeline 验证
run_pipeline.py c-blosc2 --build --max-rounds=1 --num-drivers=3：
- step1→plan_gen→step2→step3 编排衔接正常 ✅
- step3 peer 卡 git clone github.com（容器直连不通）
- 修：去掉 get_oss_fuzzer.sh 的 unset 代理，容器 --network=host 走 clash 代理（apt+git clone 都通）
- peer build 5/8 成功 ✅

### 阶段 1 完成
三模式端到端验证：step2 生成 24 driver / step3 构建 19/24 (79%) / fuzz_runner 16+6+12 crashes / 一键编排衔接正常。

### 阶段 3 libtiff pipeline 验证
- step1→plan_gen→step2→step3 编排衔接正常 ✅
- step2 生成的 driver 全被 L1 拦截（include 内部头 tiffiop.h）——step2 的 header_info 没过滤 libtiff 内部头，prompt 指引 include tiffiop.h，L1 硬拦。数据/prompt 问题，非编排问题。
- step3 崩：oss-bin 目录不存在（新项目首次跑）。修 _backup_and_clean_oss_bin 加 extract_dir.parent.mkdir(exist_ok=True)。
- 验证 pipeline 多项目扩展 + 发现 oss-bin 不存在 bug（已修）。

### 阶段 5 覆盖率聚合（框架完成，coverage 数据产出 bug 留遗留）
实现：
- get_oss_fuzzer.sh 加 DC_SANITIZER + DC_COV 环境变量（coverage 提取到 oss-bin-cov/）
- fuzz_runner 加 --coverage（profraw → llvm-profdata merge → llvm-cov export → lcov → covered_lines）
- run_cov_experiment.sh 实现 coverage 构建 + fuzz + .cov.json 保存 + aggregate
- aggregate_coverage.py 跑 union-vs-k 曲线 + summary.json/md

验证：c-blosc2 coverage 构建 focus 5 个二进制（oss-bin-cov/focus/），fuzz 跑 46 crashes，但 covered_lines=0。
原因：build.sh compile loop 用 $CC $CFLAGS，SANITIZER=coverage 时 OSS-Fuzz 应设 CFLAGS 含 coverage flags，但 profraw 大小 0（coverage 二进制没插桩）。OSS-Fuzz 的 SANITIZER 机制没传到 step3 注入的 compile loop。
留遗留：查 OSS-Fuzz base-builder 的 SANITIZER=coverage 如何设 CFLAGS + LIB_FUZZING_ENGINE，改 build.sh 或 step3 注入逻辑。

### 遗留处理
- P1 #6 run_api_scoring 硬编码：接入 setup_data["api_dependencies"] 到 scored 的 dependencies 字段（peers 暂留空，API 级 peer 数据无现成）。c-blosc2 api_dependencies=0（共现稀疏），但接入逻辑正确。
- Q7 验证：跑 step1 c-blosc2，untested 148→148（没变），tested 15→15。d 绑定 `(lib)-[:HAS_DRIVER]->(d)` scope 改对，untested 没被错误截断/膨胀 ✅。
- coverage compile loop 没插桩：OSS-Fuzz 的 compile 脚本根据 SANITIZER 设 CFLAGS（含 COVERAGE_FLAGS），但 step3 注入的 build.sh compile loop 用 $CFLAGS 时 profraw 大小 0。深层是 OSS-Fuzz SANITIZER 机制与 step3 注入的交互，需研究 compile 脚本 + helper.py build_fuzzers。留遗留。
