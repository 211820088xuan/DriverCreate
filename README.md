# Fuzz Driver 自动生成系统（driver_create）

从开源库的**源码 + 已有 harness 语料**出发，借助**知识图谱 + LLM** 自动生成 libFuzzer
fuzz driver（测试桩 / harness），再放进 **OSS-Fuzz 容器编译验证**，并由**多 Agent 编译修复
循环**把编译失败的 driver 自动修好，最终产出可直接投入 fuzz 测试的二进制。

面向 OSS-Fuzz 这类**防御性**软件健壮性测试基础设施。代码、prompt、日志里的 fuzz / driver /
payload 等均为本领域标准技术名词（指 coverage-guided fuzzing 发现内存安全 bug 并修复，非攻击语义）。

> 🔧 开发日志 `docs/log.md`、覆盖率报告 `docs/cov_*.md`、归档 `docs/archive/` 均为**本地文件**
> （`.gitignore` 已忽略 `docs/`），记录进度 / 已知问题 / 历史决策，不入仓库。

---

## 一句话理解

> **「情报收集 → LLM 生成 → 编译验证 → 自动修复」四段式流水线**，把「读懂一个库该怎么 fuzz」
> 到「产出能跑的 fuzz 二进制」这条链路尽量自动化。

核心思想有三点：

1. **喂足上下文再让 LLM 写**——先用图谱 + 模板 + 头文件签名把「这个库有哪些 API、别人怎么
   fuzz、构建长什么样」查清楚，再让 LLM 生成，减少臆造。
2. **生成即验证**——每个 driver 生成后立刻做 L1–L4 硬校验（include 白名单 / 函数调用臆造 /
   类型可见性 / 平台头），挡掉幻觉 API 和编译不过的代码，不把垃圾往后传。
3. **失败自动修**——编译失败的 driver 交给多 Agent 循环：先分诊（代码错 / 构建错），再分别派
   给对应修复 Agent，重构建，循环到全通过或达轮数上限。

---

## 目录结构

根目录只保留流水线入口脚本与配置；数据契约在 `contracts/`，各阶段组件在 `tools/` 下按 step 分子包。

```
driver_create/
├── run_pipeline.py            # 一键流水线入口（编排 step1 → headers → plan → step2 → step3）
├── step1_prepare.py           # Step1 入口（仅 main 编排；四段拆至 tools/step1_tools/）
├── step2_generate.py          # Step2 入口（仅 main + 6 入口函数；组件拆至 tools/step2_tools/）
├── step3_build.py             # Step3 入口：注入+构建+分诊+修复循环（委托 tools.step3_agent.agent_pipeline）
├── config.py                  # 全局配置：路径、Neo4j、LLM 凭证与模型、调优常量
├── .env.example               # 环境变量模板（无真实密钥）
├── .gitignore
├── README.md
│
├── contracts/                 # 数据契约层（核心 JSON schema + 读写 + 夹具）
│   ├── plans.py               #   plan_<mode>.json 读写 + schema 校验 + SAMPLE_PLAN
│   └── skeletons.py           #   skeletons.json + scenario/<场景>.json 读写 + schema 校验
│
├── tools/                     # 工具脚本与子模块包
│   ├── step0_tools/           #   全局前置：骨架库构建（跨项目，全局一次）
│   │   ├── add_call_order.py    # 给 KG CALLS 边补 order/order_last
│   │   ├── export_role_dataset.py # 导出 role 标注数据集 + 阶段 0 体检报告
│   │   ├── role_annotate.py     # Phase 5: LLM 标注 API 角色
│   │   └── skeleton_mine.py     # Phase 6: 挖骨架序列 → skeletons.json
│   ├── step1_tools/           #   Step1 四段组件 + 头文件白名单（不碰图谱的四段在此）
│   │   ├── graph_query.py      #   A 段：图谱情报（Neo4j）→ setup.json
│   │   ├── driver_template.py  #   B 段：驱动模板提取 → template.json
│   │   ├── build_profile.py    #   C 段：构建画像 → build_profile.json
│   │   ├── api_scoring.py      #   D 段：API 打分 → scored.json
│   │   └── analyze_fuzzing_headers.py # 头文件白名单（pipeline 调用，产 fuzzing_headers.json）
│   ├── step2_tools/           #   Step2 组件 + plan 生成
│   │   ├── llm_client.py       #   LLM 调用（OpenAI 兼容）+ 代码提取/校验
│   │   ├── signature_cache.py  #   头文件签名缓存 + API→头文件映射
│   │   ├── validators.py       #   L1-L4 校验器（include/调用/类型/平台头）
│   │   ├── context_builder.py  #   用法范例 + 版本 + 模板段落
│   │   ├── prompt_builder.py   #   plan 骨架槽位 → LLM prompt
│   │   ├── plan_gen.py         #   Phase 6b: 三模式 plan 生成（focus/peer/cross）
│   │   └── llm_fill_concurrent.py # 并发跑多项目 plan_gen（按需 LLM 填槽）
│   ├── step3_agent/           #   多 Agent 编译修复循环（正规 Python 包，用 -m 运行）
│   │   ├── agent_pipeline.py    #   编排器：注入 → 构建 → 分诊 → 分发修复 → 重构建，循环 ≤N 轮
│   │   ├── agent_main.py        #   主/注入 Agent + 确定性动作（restage / build / diff）
│   │   ├── agent_triage.py      #   分诊 Agent：失败 driver 判成 code（源码错）或 build（构建/链接错）
│   │   ├── agent_repair.py      #   代码修复 Agent：改 output/ 下的 driver 源码
│   │   ├── agent_build_fix.py   #   构建修复 Agent：改 build.sh / Dockerfile 的 dc-injected 标记块
│   │   └── agent_common.py      #   共享底座：路径沙箱、标记块读写、.dcbak 备份、通用 LLM tool-loop
│   └── coverage_tools/       #   fuzz 后覆盖率统计
│       └── aggregate_coverage.py # union-vs-k 曲线（origin/focus/peer/cross 四组）
│
├── scripts/                   # 构建 / fuzz / 清理 shell 与脚本
│   ├── get_oss_fuzzer.sh       #   OSS-Fuzz build_image + build_fuzzers + 提取 *_crfuzzer 二进制
│   ├── fuzz_runner.py          #   跑 oss-bin 的 *_crfuzzer 做 libFuzzer，收 crash
│   ├── run_cov_experiment.sh   #   四组 coverage 构建 + fuzz + 聚合
│   └── clear.sh                #   项目清理工具（开发用）
│
├── source_code/<project>/     # 克隆的上游项目源码（缺失时按 project.yaml 自动克隆，gitignored）
└── artifacts/                 # 所有生成产物（gitignored）
    ├── output/<project>/             #   LLM 生成产物
    │   ├── driver/[<mode>/]           #   driver 源码 *_<mode>_crfuzzer.{c,cc,cpp} + manifest
    │   ├── oss-bin/[<mode>/]          #   编译产物（二进制 *_crfuzzer）
    │   └── crashes/[<mode>/]          #   fuzz 发现的 crash / leak 种子
    ├── intermediate/<project>/        #   每项目中间产物（setup / template / scored / build_profile / plan_<mode> …）
    ├── intermediate/_shared/          #   跨项目共享：skeletons.json / scenario/ / role_labels.jsonl
    ├── logs/                          #   pipeline 运行日志 pipeline_<project>_<ts>.log
    └── coverage_exp/<TS>/             #   覆盖率实验产物
```

> **路径全部集中在 [`config.py`](config.py)**：`DRIVER_CREATE_DIR` 之下派生 `OUTPUT_DIR` /
> `INTERMEDIATE_DIR` / `SRC_DIR` / `PIPELINE_LOGS_DIR`，改目录只需改 config 一处。外部绝对路径
> `OSS_FUZZ_DIR=/root/gyx/oss-fuzz`、`PROJECTS_DIR=/root/gyx/projects` 不受本项目布局影响。

---

## 整体流程

```
┌── run_pipeline.py 编排 ──────────────────────────────────────────────────┐
│                                                                          │
│  step1_prepare  →  [analyze_fuzzing_headers]  →  [skeleton_mine + plan_gen]  │
│    情报收集           头文件白名单              全局骨架池 + 三模式 plan      │
│  (graph_query/     (tools/step1_tools)       (tools/step0_tools +           │
│   driver_template/                            tools/step2_tools)           │
│   build_profile/                                                            │
│   api_scoring)                                                              │
│                                                                          │
│                                     →  step2_generate（per mode） ─┐      │
│                                          LLM 填骨架槽位 + L1-L4 校验  │      │
│                                                                        │      │
│                                        默认停在这里（不加 --build）──┘      │
│                                                                          │
│                       ── 加 --build 才进入 ──                            │
│                                                                          │
│  step3_build（第三阶段 · 内部委托 tools.step3_agent.agent_pipeline）      │
│    注入 → 构建 → 分诊 → 分发修复 → 重构建   循环 ≤ max_rounds              │
└──────────────────────────────────────────────────────────────────────────┘
```

- **step2 生成后默认停下**，让你先审源码；确认无误再加 `--build` 进第三阶段。
- **`--build` 进入 `step3_build.py`**：默认委托 `tools.step3_agent.agent_pipeline` 跑多 Agent 修复循环——
  主 Agent 把 driver 注入 `oss-fuzz/projects/<project>/` 的 build.sh / Dockerfile 标记块并构建；
  分诊 Agent 把失败项分成「代码错 / 构建错」，分别交给代码修复 / 构建修复 Agent；重构建，
  循环到全通过或达 `max_rounds`。
- **无 DeepSeek 凭证时优雅降级**：修复循环只做「注入 + 构建」，不进 LLM 修复；也可显式用
  `step3_build.py <project> --no-repair` 走纯确定性构建 + 比对。

---

## 环境要求

| 依赖 | 用途 | 必需性 |
|---|---|---|
| Python 3.10+ | 运行全部脚本 | 必需 |
| Docker | OSS-Fuzz 容器编译 / fuzz 运行 | `--build` 及 fuzz 阶段必需 |
| DeepSeek（OpenAI 兼容 API） | step2 生成 + agent 修复的默认 LLM | 生成 / 修复必需 |
| Neo4j | 图谱情报（step1 A 段） | 可选，缺失时 step1 优雅降级 |
| OSS-Fuzz 仓库 `/root/gyx/oss-fuzz` | Docker 构建环境（`infra/helper.py` + `projects/<p>/`），`scripts/get_oss_fuzzer.sh` 通过 `OSS_FUZZ_DIR` 环境变量引用 | `--build` 必需 |

> ⚠️ OSS-Fuzz 镜像构建必须在 `/root/gyx/oss-fuzz` 目录下执行；容器内 clone/apt/wget 卡住的头号
> 根因是**代理未进环境变量**，跑 `--build` 前确认 `https_proxy` 已设置。

---

## 快速开始

```bash
cd /root/gyx/driver_create

# 一键：生成 5 个 driver/模式（生成后停在 step2，先让你审源码）
python3 run_pipeline.py c-blosc2 --num-drivers=5

# 一键 + 编译修复循环（注入 → 构建 → 分诊 → 修复 → 重构建）
python3 run_pipeline.py c-blosc2 --num-drivers=5 --build

# 只做情报收集，跳过 LLM 生成
python3 run_pipeline.py c-blosc2 --skip-llm
```

`run_pipeline.py` 参数：

| 参数 | 说明 |
|---|---|
| `--num-drivers=N` | 生成 N 个 driver/模式（默认 5，是上限不是目标） |
| `--skip-llm` | 跳过 step2（只做情报收集） |
| `--skip-headers` | 跳过 analyze_fuzzing_headers（默认开启，用于增强 step2 头文件约束） |
| `--mode=focus\|peer\|cross\|all` | 三模式之一或全跑（默认 all） |
| `--build` | 进入第三阶段 `step3_build.py`（默认多 Agent 编译修复循环） |
| `--max-rounds=N` | step3 修复循环最大轮数（默认 3） |
| `--log=PATH` | 指定日志路径（默认 `artifacts/logs/pipeline_<project>_<ts>.log`） |

> **kill switch**：环境变量 `DC_DISABLE_AGENT_REPAIR=1` → 修复循环只注入 + 构建，不进 LLM 修复。

---

## 分步 / 单模块运行

根目录脚本直接按文件跑；`tools/step3_agent/` 包内模块用 **`python3 -m tools.step3_agent.<模块>`** 跑
（包内用绝对 import + sys.path 引导，不能 `python3 tools/step3_agent/xxx.py` 直跑）：

```bash
# —— 流水线各步（根目录脚本）——
python3 step1_prepare.py <project>              # 情报收集 + API 打分 + 构建画像
python3 tools/step1_tools/analyze_fuzzing_headers.py <project>  # 头文件白名单（pipeline 自动调，也可单跑）
python3 step2_generate.py <project> [N] [--mode=focus|peer|cross|all]  # LLM 生成 N 个 driver
python3 step3_build.py <project>                # 第三阶段：注入 + 构建 + 分诊 + 修复循环（默认）
python3 step3_build.py <project> --max-rounds=N # 指定修复循环最大轮数（默认 3）
python3 step3_build.py <project> --mode=focus  # 三模式之一（focus/peer/cross）
python3 step3_build.py <project> --no-repair    # 确定性兜底：restage + 构建 + 比对，不修复
python3 step3_build.py <project> --no-build     # 只比对现有 oss-bin 产物，不重构建

# —— tools.step3_agent 包（-m 形式；step3_build 默认就委托 agent_pipeline，下面供单独调试）——
python3 -m tools.step3_agent.agent_pipeline <project> [--max-rounds=N] [--mode=focus|peer|cross]
python3 -m tools.step3_agent.agent_main <project> --diff    # 期望 vs 实际产物比对（确定性，不需 Docker/LLM）
python3 -m tools.step3_agent.agent_main <project> --diff --mode=focus  # 按 mode 比对
python3 -m tools.step3_agent.agent_triage <project> [failed_target ...] [--mode=focus|peer|cross]
python3 -m tools.step3_agent.agent_build_fix <project> [--mode=focus|peer|cross]

# —— fuzz + 覆盖率（scripts/）——
python3 scripts/fuzz_runner.py <project> [--mode=<m>] [--max-time=300] [--workers=2] [--coverage]
bash scripts/run_cov_experiment.sh <project> [--max-time=60] [--workers=2]
bash scripts/clear.sh <project> [--keep-output] [--dry-run]  # 清理注入痕迹
```

---

## 各步骤详解

### Step 1 · 情报收集（`step1_prepare.py` + `tools/step1_tools/`）

`step1_prepare.py` 仅保留 `main()` 编排，四段拆至 `tools/step1_tools/`（段间只通过 `setup_data` /
`template_data` 字典传值，无跨段函数调用）：

1. **A 图谱查询**（`graph_query.py`，唯一 Neo4j 层）— 从 Neo4j 取项目 Scenario、已测 / 未测 API、
   同类项目的调用模式、API 共现关系（含 `order_last` 顺序一致率）。Neo4j 缺失时本步优雅降级。
2. **B 驱动模板提取**（`driver_template.py`）— 正则分析已有 fuzz driver 语料，抽出 include、
   init/cleanup 模式、数据消费策略。含 `_extract_skeleton`（**返回布尔特征集** `has_size_guard`/
   `has_loop` 等，非调用序列骨架，勿与 `skeleton_mine` 的角色序列混淆）。
3. **C 构建 Profile**（`build_profile.py`）— 解析 OSS-Fuzz 的 Dockerfile / build.sh，识别
   CMake / Autotools / Meson 构建方式，include 路径、链接库、C++ 标准。
4. **D API 打分**（`api_scoring.py`）— 给候选 API 排序（未测 +15、peer 用法、信息完整度加分）。

**输出**（`artifacts/intermediate/<project>/`）：`setup.json`、`template.json`、
`build_profile.json`、`scored.json`。

### 头文件白名单（`tools/step1_tools/analyze_fuzzing_headers.py`，默认开启）

扫描项目已有 fuzzer 的头文件使用，产出可安全 `#include` 的白名单与可用 helper 符号清单，
收紧 step2 的 include 约束，进一步压低幻觉 API。**输出**：`fuzzing_headers.json`。

### Step 2 · LLM 生成（`step2_generate.py` + `tools/step2_tools/`）

`step2_generate.py` 仅保留 `main()` + 6 个入口/辅助函数（`load_template` / `derive_driver_name` /
`_derive_name_fallback` / `generate_one_driver_from_plan` / `_run_peer_cross_mode` / `main`），
组件拆至 `tools/step2_tools/`：

- `llm_client.py` — LLM 调用（OpenAI 兼容）+ `extract_code` / `is_valid_driver`
- `signature_cache.py` — 扫头文件建函数签名/结构体/常量缓存 + API→头文件映射
- `validators.py` — L1 include 白名单 / L2 函数调用臆造 / L3 类型可见性 / L4 平台头
- `context_builder.py` — 用法范例 + 版本 + 模板段落（喂给 prompt）
- `prompt_builder.py` — `build_prompt_from_plan`：从 plan 骨架槽位 + 上下文 → LLM prompt

**骨架驱动生成流程**（取代旧的「API 前缀分组 + LLM 设计序列」）：

1. **加载 plan** — `_run_peer_cross_mode` 读 `intermediate/<project>/plan_<mode>.json`（由 `plan_gen.py` 产出）。
2. **建 prompt** — `build_prompt_from_plan` 把骨架槽位 + 候选 API 签名 + 用法范例 + 模式侧重段拼成 prompt。
3. **LLM 并行生成** — 多线程 worker，每个生成一个 driver（fast 模型 3 次 → strong 兜底 3 次）。
4. **L1–L4 硬校验** — L1/L4 硬拦，L2 警告（build 阶段兜底），L3 硬拦。
5. **落盘** — `output/<project>/driver/<mode>/*_<mode>_crfuzzer.{c,cc,cpp}` + `manifest.json`。

三模式（focus/peer/cross）并列，每项目都跑：focus 挖深度（本项目序列插未测 API）、
peer 拓广度（结构距离 ==2）、cross 换结构（距离 ≥3）。详见 `contracts/plans.py` 的 plan schema。

### 第三阶段 · 编译验证与修复（`step3_build.py` + `tools/step3_agent/`）

`run_pipeline.py --build` 调 `step3_build.py`，默认委托 `tools.step3_agent.agent_pipeline` 跑
多 Agent 编译修复循环。构建模型：

1. driver 源码在 `artifacts/output/<project>/driver/[<mode>/]`。
2. **注入** — 主 Agent 把编译循环写进 `oss-fuzz/projects/<project>/` 的 build.sh / Dockerfile 的
   `dc-injected` 标记块（`# >>> dc-injected >>>` … `# <<< dc-injected <<<`，单一来源定义在
   `agent_common.MARKER_BEGIN/END`）。
3. **restage** 到 `oss-fuzz/projects/<project>/`（Docker 构建上下文，manifest-guarded，首轮 touch-none）。
4. 跑 `scripts/get_oss_fuzzer.sh <project> [<dc_only>] [<mode>]`（build_image → build_fuzzers →
   提取到 `output/<project>/oss-bin/[<mode>/]`）。
5. 期望产物（driver stem）比对 `oss-bin/[<mode>/]` 实际产物，报告成功 / 失败。

**修复循环**（在比对之后）：分诊失败项 → 代码错交 `agent_repair`、构建错交 `agent_build_fix`
→ 重 restage + 重构建，循环至全通过或达 `max_rounds`。同一轮内**先构建修复、再代码修复**
（链接 / include 错误会掩盖代码错误）。产物落 `agent_build_summary[_<mode>].json`。

**确定性降级**（不注入、不进 LLM 修复）：

| 命令 | 行为 |
|---|---|
| `step3_build.py <project>` | 默认：注入 + 构建 + 分诊 + 修复循环（委托 agent_pipeline） |
| `step3_build.py <project> --max-rounds=N` | 同上，指定修复循环最大轮数（默认 3） |
| `step3_build.py <project> --no-repair` | 只跑构建模型第 2–4 步（restage + 构建 + 比对），落 `step3_summary.json` |
| `step3_build.py <project> --no-build` | 只比对现有 `oss-bin/` 产物，连构建都跳过 |

> 无 DeepSeek 凭证时，即便走默认路径，`agent_pipeline` 内部也会自动降级为「只注入 + 构建」，
> 与 `--no-repair` 效果一致；`DC_DISABLE_AGENT_REPAIR=1` 可强制该降级。

> **`source_code/<project>` 自动克隆**：`step1_prepare.py` / `step3_build.py` / `agent_pipeline.py`
> 执行前会检查本地源码，缺失则按 `oss-fuzz/projects/<project>/project.yaml` 的 `main_repo` 自动克隆。

---

## Fuzz 测试

编译产物在 `artifacts/output/<project>/oss-bin/[<mode>/]`，跑 libFuzzer（用 `scripts/fuzz_runner.py`
自动跑 base-runner 容器，或手动）：

```bash
cd /root/gyx/driver_create
# 自动（推荐）：跑 oss-bin 下所有 *_crfuzzer，收 crash 到 output/<p>/crashes/<mode>/
python3 scripts/fuzz_runner.py c-blosc2 --mode=focus --max-time=60

# 手动单个
mkdir -p artifacts/crashes/c-blosc2/decompress_flush_fuzzer
docker run --rm \
  -v $(pwd)/artifacts/output/c-blosc2/oss-bin/focus:/out:ro \
  -v $(pwd)/artifacts/crashes/c-blosc2:/crashes \
  gcr.io/oss-fuzz-base/base-runner:ubuntu-24-04 \
  bash -c "mkdir -p /tmp/c && /out/decompress_flush_fuzzer -max_total_time=60 -artifact_prefix=/crashes/ /tmp/c"
```

crash 种子在 `artifacts/output/<project>/crashes/<mode>/`，复现把 crash 文件挂进去即可。
覆盖率实验（四组 origin/focus/peer/cross 的 union-vs-k 曲线）跑 `scripts/run_cov_experiment.sh`，
聚合用 `tools/coverage_tools/aggregate_coverage.py`。

---

## 配置（环境变量）

| 变量 | 说明 | 默认值 |
|---|---|---|
| `DEEPSEEK_API_KEY` | DeepSeek API Key（step2 + agent 修复默认 LLM） | - |
| `DEEPSEEK_BASE_URL` | DeepSeek endpoint | `https://api.deepseek.com` |
| `DEEPSEEK_MODEL` / `DEEPSEEK_FAST_MODEL` | 强 / 快模型 | `deepseek-v4-pro` / `deepseek-v4-flash` |
| `NEO4J_URI` / `NEO4J_USER` / `NEO4J_PASSWORD` | Neo4j 图谱（可选） | `bolt://localhost:7687` … |
| `OSS_FUZZ_DIR` / `SH_DIR` / `PROJECTS_DIR` | 外部目录（oss-fuzz / sh / 已有 driver 语料） | `/root/gyx/oss-fuzz` 等 |
| `DC_DISABLE_AGENT_REPAIR` | `1` → 修复循环只注入 + 构建，不进 LLM 修复 | - |
| `DC_MAX_COMPILE_STEPS_PER_DRIVER` | 单 driver 代码修复 agent 的最大编译步数 | `3` |
| `DC_GLOBAL_BUILD_BUDGET` | 全局 Docker 构建次数上限（防 N×3×3 空转） | `30` |
| `https_proxy` | HTTPS 代理（Docker 内 git clone GitHub 用） | - |

完整清单见 [`config.py`](config.py)、`.env.example`。

---

## 已验证项目（历史节点）

| 项目 | 生成 | 编译成功 | fuzz 发现 |
|---|---|---|---|
| json-c | 10 | 6 (60%) | heap-use-after-free, leak |
| c-blosc2 | 10 | 10 (100%) | heap-buffer-overflow, leak |
| libxml2 | 10 | 10 (100%) | crash, leak |
