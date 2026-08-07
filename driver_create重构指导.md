# driver_create 重构指导文档

**给执行者（OpenCode）的说明**

这份文档给的是**意图、判据、验收标准**，不是逐行改法。原因是：写这份文档的人只完整读过 `step1_prepare.py`、`config.py`、`run_pipeline.py`、`step3_build.py`，**没有读过 `step2_generate.py` 的主体（3170 行）、`agent/` 整个包、`get_oss_fuzzer.sh`**。

因此：

- 标 `【已验证】` 的内容有真实数据或代码支撑，直接执行
- 标 `【需先验证】` 的内容来自二手转述，**先按给出的判据确认，确认不成立就报告并跳过，不要硬改**
- 标 `【自行定位】` 的内容需要你读代码后决定实现方式，本文只给目标状态和接口契约

已知转述失真两例（用于校准信任度）：交接材料称 `ensure_domain_groups` 在 `step1_prepare.py`，实际在 `step2_generate.py`；称 `agent_triage` 有「粗切+细切」，实际没有。**没读过的文件里的描述，失真率没有理由更低。**

---

## 1. 这个重构在做什么

`driver_create` 是知识图谱驱动的 OSS-Fuzz fuzz driver 自动生成流水线。当前版本用「按 API 名前缀分领域 + LLM 设计调用序列」来决定生成什么 driver，这条路要**整体废弃**，换成**骨架驱动**：

1. 从图谱里已有的真实 driver 挖出**调用骨架**（角色序列，如 `create → configure → data_sink → process → destroy`）
2. 对每个目标项目，按骨架与该项目现有 driver 形状的**结构距离**分出三种模式的候选
3. 每个骨架的槽位用该项目的真实 API 填充，生成 driver

三种模式是**并列**的（不是降级链），每个项目三种都跑：

| 模式 | 骨架来源 | 意图 |
|---|---|---|
| **focus** | 本项目已有 driver 的真实序列，往里插未调用过的 API | 挖深度 |
| **peer** | 骨架池中与本项目现有形状**距离 == 2** 的（最近但没做过） | 拓广度 |
| **cross** | 骨架池中与本项目现有形状**距离 ≥ 3** 的（结构最远） | 换结构 |

---

## 2. 硬口径（已用真实数据定死，不要改）

### 2.1 角色词表【已验证】

进入骨架序列的角色只有 **5 个**：

| 角色 | 含义 |
|---|---|
| `create` | 让对象从无到可用：分配并返回句柄，或就地初始化（`zip_open`、`mbedtls_ssl_init`、`ZSTD_createCCtx`） |
| `configure` | 在已有句柄上设参数、注册回调、启用特性（`SSL_CTX_set_max_proto_version`、`archive_read_support_format_zip`） |
| `data_sink` | 把外部字节流喂进对象——fuzz 输入的入口（`archive_read_open_memory`、`ZSTD_seekable_initBuff`、`json_from_string`） |
| `process` | 业务动作：解析/解码/编码/变换/执行/迭代推进（`ZSTD_decompress`、`rdp_recv_data_pdu`、`archive_read_next_header`） |
| `destroy` | 释放资源、收尾、关闭（`ZSTD_freeCCtx`、`archive_write_close`） |

**另有 `query` 和 `unknown` 两个标签，但它们不进骨架序列。**

- `query`：读状态、取属性、查找，不改变对象。**从序列中整个剔除**。实测它占标注量的 28%，且位置随意，保留会把形状打散（形状数 35→25，跨项目匹配率 4%→10%）
- `unknown`：LLM 无法判定或缺描述。从序列剔除

合并决策（**这些合并是实测出来的，不要拆开**）：

- `init`（返回 void 的就地初始化）并入 `create`
- `iterate` 并入 `process`——实测这两者的边界是**项目 API 设计习惯**，不是场景结构。libarchive 用 `archive_read_next_header`（迭代器风格）推进、zstd 用 `ZSTD_decompressStream`（流函数风格）推进，语义相同。合并后跨项目匹配率从 10% 跳到 46%
- `finalize` 并入 `destroy`
- **`data_sink` 绝不能并入 `process`**——它是 fuzz 输入入口，合并后无法表达「字节流从哪进」

`data_sink` 与 `process` 重叠时（如 `plist_from_xml` 既吃字节流又解析）：**能直接接收原始字节流的优先标 `data_sink`**。注意字典/配置类的 `const void* + size` 参数（如 `ZSTD_CCtx_loadDictionary`）不是 fuzz 输入，标 `configure`。

### 2.2 序列构造【已验证】

```
按 order_last 升序排列该 driver 的所有 CALLS 边
  → 映射为角色
  → 剔除 query 和 unknown
  → 折叠连续重复（create,configure,configure,decode → create,configure,decode）
  → 得到骨架序列
```

**顺序不能颠倒**：必须先剔除再折叠。若先折叠，`configure, unknown, configure` 中两个 configure 不相邻、折不掉，剔除后留下重复。

**排序必须用 `order_last`，不是 `order`**【已验证】。两者都是每个 driver 内 `0..n-1` 的稠密排名（`order` 按首次出现，`order_last` 按末次出现，约 30% 的边两者不同）。实测用 `order` 会产出 `create→configure→data_sink→destroy→process` 这种 destroy 排在 process 前面的失真形状，因为循环里的 `free` 首次出现早；`order_last` 给出的是 `create→configure→data_sink→process→destroy`。换用 `order_last` 后形状数 23→21、跨项目匹配率 46%→54%。

**driver 丢弃阈值**：`unknown` 占比 > 1/3 **或** 剔除后剩余长度 < 4，满足其一则整个 driver 不参与挖掘。后一条与「边数 ≥4 才算可用 driver」口径统一。

### 2.3 骨架匹配一律用编辑距离 ≤ 1【已验证】

这条口径贯穿**四处**，必须全部一致，否则会静默错位：

1. peer/cross 的距离分档
2. holdout 验证
3. 三模式 plan 的去重检查
4. 「本项目是否已覆盖某形状」的判断

实测精确匹配是错的判据：NetworkProtocol 用精确形状共享只有 12% 跨项目，改用编辑距离 ≤1 是 46%，≤2 是 79%。

**随机基线（对照，必须记住）**：用 5 个角色随机生成 ~35 条骨架池，编辑距离 ≤1 能描述 CompressionArchive driver 的 42%、NetworkProtocol driver 的 12%。所以 CA 的高匹配率有相当部分是形状空间小造成的，**NP 上的数字（46%/58% vs 基线 12%）才是真信号**。任何新的匹配率数字都要对着基线读。

### 2.4 peer / cross 按结构距离分档【已验证】

对目标项目 P：

```
S_P = P 现有 driver 的骨架形状集合
对骨架池中每条候选骨架 k：
    d(k) = min(edit_distance(k, s) for s in S_P)
    d(k) <= 1  →  本项目已覆盖，跳过
    d(k) == 2  →  peer 候选
    d(k) >= 3  →  cross 候选
```

**这取代了原设计的「peer 取同场景骨架 / cross 取跨场景骨架」。** 原设计被实测证伪：NetworkProtocol 的 driver 被 CompressionArchive 骨架描述（58%）比被同场景其他项目描述（46%）**还高**。骨架好不好用取决于骨架本身的规范程度，不取决于它属于哪个场景。

实测 19 个项目全部两档都有候选（骨架池仅 55 条时）。例：libarchive 已覆盖 17 / peer 22 / cross 16；zstd 24/14/17；net-snmp 18/12/25。**例外**：`qpid-proton`（自有形状仅 1 条）peer 档为 0，`freerdp` peer 档仅 1——这类项目 peer 会退化，报表用 `n/a` 而非 0。

`cross` 档候选常有 40+ 条，**必须排序取前 N**：按骨架的**支撑 driver 数**降序（形状被越多真实 driver 印证越可信）。peer 档同理。

`S_P` 为空（项目 0 个 driver）时：**focus 不可用**（没有本项目序列可插），peer/cross 退化为「按支撑 driver 数取前 N」。这些项目也没有 origin 基线可比。

### 2.5 场景仍然有用，但只用于置信度

场景标签不再决定 peer/cross，但仍用于给骨架标置信度。按「边数 ≥4 的可用 driver 数」分三档【已验证】：

| 档 | 场景 |
|---|---|
| 正常（≥20） | NetworkProtocol 51、CompressionArchive 53、ImageProcessing 46、NetworkTrafficAnalysis 43、DatabaseStorage 36、CryptoSecurity 35、SystemEmbedded 27、BinaryReverseAnalysis 27、FontTextProcessing 23 |
| low-confidence（10-19） | DataSerialization 14、AudioVideoCodec 14 |
| 不进 skeletons（<10） | DocumentProcessing 7、ProgrammingLanguage 7、WebFramework 6、IoTEmbeddedNetwork 1、3DGraphicsGeometry 0、LoggingAnalysis 0 |

注意 ImageProcessing 的 46 个可用 driver 里 leptonica 占 40（87%），NetworkTrafficAnalysis 的 43 个里 ndpi 占 41（95%）——**这两个场景的骨架要额外标「单库主导」**，它们的形状收敛可能只是同一项目的写法一致。

---

## 3. 负面清单：已否决的方案，不要重新引入

| 已否决 | 否决理由 |
|---|---|
| 按 API 名前缀分领域（`DOMAIN_PREFIX_RULES`） | 现有 13 条规则全是 c-blosc2 的名字（`blosc2_schunk`/`b2nd`/`blosclz`…），是单项目硬编码，对其他项目无效 |
| 三模式降级链（focus 失败退 peer 退 cross） | 降级链下 cross 只在少数项目触发，样本量太小无法验证有效性。改为三种并列，每项目都跑 |
| 强制三模式产出数量对齐 | 强制对齐要给 cross 补变体，而 cross 的变体结构完全相同，会稀释 cross 自己的每-driver 指标 |
| 用签名形状规则决定填槽位角色 | 骨架里的角色名来自 description 语义，用签名形状填会导致两套标签指向不同集合。实测签名规则在 libarchive 的未调用 API 池上只命中 19%（574 中 110），且对 `png_write_image` 这类业务动作一条不中——而业务动作正是主槽位 |
| cross 填不满槽位时硬凑 | 宁可少生成也不产残缺 driver。但**必须记录跳过原因**（见 4.3 的 `skipped` 字段） |
| crash 引导选 API | 当前目标是覆盖率；crash 栈指向被反复走过的密集区，方向相反 |
| 用 `crash_count` 排序选 peer 项目 | 实测 libspng 的 peer 前三名（openexr/kimageformats/libvips）全是 0 driver 项目。改用 `driver_count` 排序 |

---

## 4. 数据契约

三份 JSON。**先把这三份定死并写好 loader，再动生成逻辑**——它们是 Section E 和 step2 的共同接口。

### 4.1 `_shared/skeletons.json`

跨项目共享，全局算一次。

```json
{
  "vocab_version": "v4",
  "order_field": "order_last",
  "skeletons": [
    {
      "id": "sk_0001",
      "sequence": ["create", "configure", "data_sink", "process", "destroy"],
      "support_drivers": 18,
      "support_projects": ["libarchive", "c-blosc2"],
      "scenarios": {"CompressionArchive": 18},
      "scenario_confidence": "normal",
      "single_lib_dominated": false,
      "slot_multiplicity": {"configure": [1, 4], "process": [1, 2]},
      "example_drivers": ["libarchive/fuzz_archive.c"],
      "source_enrichment_rate": 0.98
    }
  ]
}
```

字段用途：

- `support_drivers` / `support_projects`：peer/cross 档内排序的依据，也是「这条骨架可不可信」的判据
- `slot_multiplicity`：某角色槽在真实 driver 里典型填几个 API（由折叠前的重复次数统计得来）。**step2 生成时需要它来决定一个槽填几个 API**
- `single_lib_dominated`：支撑 driver 全来自一个项目时为 true，cross 借它要谨慎
- `source_enrichment_rate`：支撑项目的平均富化率。低富化率项目挖出的骨架，其角色是从裸名标的，可信度低

**命名注意**【已验证】：`step1_prepare.py` 里已有一个 `_extract_skeleton`，返回的是布尔特征集（`has_size_guard`/`has_loop`/…），**与本文的「骨架」是完全不同的东西**。新代码一律用 `call_skeleton` 命名，避免混淆。

### 4.2 `_shared/scenario/<场景>.json`

```json
{
  "scenario": "CompressionArchive",
  "usable_drivers": 53,
  "confidence": "normal",
  "single_lib_dominated": false,
  "project_distribution": {"libarchive": 25, "zstd": 20, "c-blosc2": 4},
  "peer_projects_ranked": ["libarchive", "zstd", "c-blosc2"],
  "skeleton_ids": ["sk_0001", "sk_0007"],
  "data_strategy_distribution": {"byte-sliced": 20, "direct": 18, "tlv": 9}
}
```

- `peer_projects_ranked` 按 `driver_count` 排，**不是 `crash_count`**（见负面清单）
- `data_strategy_distribution` 可直接复用 `step1_prepare.py` 里现成的 `_classify_data_strategy`（tlv/producer/byte-sliced/direct）【已验证存在】

### 4.3 `<project>/plan_{focus,peer,cross}.json`

**这是最关键的契约，step2 完全依赖它。**

```json
{
  "mode": "peer",
  "project": "libpng",
  "vocab_version": "v4",
  "drivers": [
    {
      "id": "peer#1",
      "skeleton_id": "sk_0007",
      "skeleton": ["create", "configure", "data_sink", "process", "destroy"],
      "distance_to_own": 2,
      "slots": [
        {
          "index": 0,
          "role": "create",
          "fill_count": [1, 1],
          "candidates": [
            {"api": "png_create_read_struct", "signature": "...", "header": "png.h",
             "handle_type": "png_structp", "confidence": "llm"}
          ]
        }
      ],
      "evidence": {
        "why": "结构距离 2；本项目现有 3 条形状均无 data_sink 槽",
        "skeleton_support": {"drivers": 18, "projects": ["libarchive", "c-blosc2"]},
        "source_scenario": "CompressionArchive"
      },
      "source_tier": "peer",
      "prerequisite": null,
      "duplicate_of": null
    }
  ],
  "skipped": [
    {"skeleton_id": "sk_0012", "failed_slot": 2, "failed_role": "process",
     "reason": "no_candidate", "candidates_found": 0}
  ]
}
```

关键字段的**存在理由**（不要因为「看起来冗余」删掉）：

- **`evidence`**：直接用作论文里「为什么生成这个 driver」的证据。不是调试信息
- **`source_tier`**：让「跨结构生成」变成可数指标
- **`skipped`**：**必须有**。cross 填不满就跳过骨架，如果不记录，实验出来 cross 数字低时无法区分「跨结构迁移没用」和「槽位填不上」——后者是工具缺陷，会污染整个实验结论
- **`prerequisite`**：focus 规则 2 用（见 7.1），值为 `null` 或 `"inferred_by_llm"`
- **`duplicate_of`**：三份 plan 生成后做骨架级去重检查，重复的标记但**不删除**（两模式各跑各的是实验设计的一部分，删了破坏对照）。分析时可算出三模式的想法重叠率
- **`fill_count`**：来自 `slot_multiplicity`，告诉 LLM 这个槽填几个 API

---

## 5. Phase A：结构与配置

不依赖骨架数据，可立即开工。

### 5.1 `config.py`

现状【已验证】：只有 `intermediate_for(project)`，没有 `_shared/` 和 mode 相关常量。

新增：

```python
def shared_dir():                       # artifacts/intermediate/_shared/
def scenario_dir():                     # artifacts/intermediate/_shared/scenario/
def output_for(project, mode=None):     # artifacts/output/<project>/<mode>/
def plan_path(project, mode):           # artifacts/intermediate/<project>/plan_<mode>.json
```

`mode=None` 时 `output_for` 退回原路径，保证旧数据可读。

**这批常量由 Phase A 定义，其余脚本一律引用，不要各处硬编码路径。**

### 5.2 `run_pipeline.py`

现状【已验证】：无 `--mode`；`--num-drivers` 只透传给 step2，step1 不接收；调用 `step3_build.py` 时不传任何参数（所以 `--max-rounds` 走 pipeline 时用不上）。

改动：

- 加 `--mode focus|peer|cross`，默认三种都跑
- `--num-drivers` 同时透传给 step1（它要按 N 裁 plan）和 step2
- `--max-rounds` 透传给 step3

### 5.3 `step3_build.py` 与产物隔离

step3 主体逻辑不改，但三模式产物必须隔离，否则同名 driver 互相覆盖：

- `collect_driver_sources` 扫 `<mode>` 子目录
- driver 文件名带模式标记
- `oss-bin/` 按模式分目录

**验收**：三种模式跑完后，`oss-bin/` 下能同时看到三套二进制，互不覆盖。

### 5.4 plan loader 与测试夹具

先写 `plan_*.json` 的读写接口 + **一份手写的样例 plan** 作为测试夹具。这样 step2 的改造可以在没有真实 plan 的情况下先跑通。

---

## 6. 缺陷修复

按「不修会不会让实验数据变成假的」排，**不按工作量排**。

### 6.1 P0：不修则实验数据无效

| # | 缺陷 | 状态 |
|---|---|---|
| 1 | `get_oss_fuzzer.sh` 的 `oss-bin/` 与 `build/out/` 都不清理，陈旧二进制被当成编译成功 | 【需先验证】没读过这个脚本。确认后修：每轮构建前清空这两个目录。**这是优先级最高的一条**——不修则覆盖率数字直接是假的，整个实验白做 |
| 2 | `step1_prepare.py` 四个 `LIMIT` 都没有 `ORDER BY`（`untested_apis`/`tested_apis` 各 500、`all_apis` 2000、`peer_driver_patterns` 50） | 【已验证】真实数据上 c-blosc2 的 `untested_apis` 恰好是 500，确认被截断。加确定性 `ORDER BY`，否则跨次运行拿到不同 API 集合，实验不可复现 |
| 3 | `agent_repair.tool_grep_symbol` 的匹配语义 | 【需先验证】**先读代码确认**：是精确词边界匹配还是子串匹配？搜不搜注释和字符串字面量？整套「undefined reference 用符号查证消歧」的分诊全压在它上面，只要偏宽松则 code/build 分诊整体反向，静默污染所有三模式的构建成功率。**确认前不要改任何分诊逻辑** |

### 6.2 P1：影响正确性但不使数据失效

| # | 缺陷 | 状态 |
|---|---|---|
| 4 | `DC_OFFICIAL_RC` 无人读，官方构建整体失败时全部 driver 报缺库，三轮修复空耗 | 【需先验证】 |
| 5 | `agent_triage.extract_target_error_lines` 里 `in_scope` 永不复位，一个 target 名出现后整个 log 的错误行都算它的 | 【需先验证】注意：交接材料称此处有「粗切+细切」，已确认**不是**当前实现，说明这块的转述不可靠 |
| 6 | `run_api_scoring` 里 `"dependencies": []` 和 `"peers": []` 两处硬编码，把 Q9 算好并已写进 `setup.json` 的 `api_dependencies` 丢在 `scored.json` 之外 | 【已验证】修法是把 setup 的 `api_dependencies` 接进 scored 条目，**不需要重写 Q9** |
| 7 | `step1_prepare.py` Q7 的「未测」scope 错：`OPTIONAL MATCH (d)-[:CALLS]->(a)` 里 `d` 无标签无绑定，实际语义是「全图无人调用」而非「本项目未测」 | 【已验证】 |
| 8 | `_find_complete_driver_examples` 只从本项目取范例，本项目没 driver 就一个范例都没有 | 【需先验证】改为 peer 模式扩到同场景 |

### 6.3 P2：效率与可观测性

| # | 缺陷 | 状态 |
|---|---|---|
| 9 | 编译修复不自验：`REPAIR_ORDER=["build","code"]`，build 修复改完 `build.sh` 不验证就进 code 修复。`build.sh` 被改坏则所有 replay 全失败 | 【需先验证】 |
| 10 | replay 成本上限可达 90 次 docker 构建（`DC_MAX_COMPILE_STEPS_PER_DRIVER=3` × N 个失败 driver × 3 轮） | 【需先验证】加全局上限 |
| 11 | 日志被 replay 冲掉：`: > $OUTPUT_LOG` + 每次 replay 重跑脚本，pipeline 结束后日志是最后一次单 driver replay 的 | 【需先验证】 |
| 12 | `.dcbak` 第二次运行被污染（`session_backup_injectables` 用 `overwrite=True`），原始 `build.sh` 永久丢失 | 【需先验证】**先确认 `backup_build_file` 的 `overwrite=True` 是否无条件覆盖**，这决定该缺陷成不成立 |

### 6.4 随 step2 大改顺手清理（都在 `build_prompt` 里）

| # | 缺陷 | 状态 |
|---|---|---|
| 13 | KG 覆盖循环把 `_format_scored_sig` 整个作废（覆盖条件是其严格超集），签名接地改动一行都没进 prompt | 【需先验证】反正 `build_prompt` 要重写，直接删 |
| 14 | `header_path` 判据恒为假——KG 里该属性从未写入（全库 0% 覆盖） | 【已验证】真实数据上 `header_path` 覆盖率 0/1623。删掉这个分支，头文件指引统一收进一处 |
| 15 | 读了 step1 不产的键：`verify_patterns` / `data_flows` / `classification_sources` / `extra_defines`，对应 prompt 段落永远为空；`fuzzing_headers.json` 整个文件 step1 不产，但 prompt 仍指引 LLM 去看不存在的章节 | 【需先验证】 |

### 6.5 已排除（验证后不成立，不要再修）

`_crfuzzer` 命名全链路对齐、硬编码 `src/`→`output/` 路径、Docker COPY 层缓存导致改完源码进不了容器。

---

## 7. Phase B：Section E —— 三模式 plan 生成

新增在 `step1_prepare.py` 里（或独立模块，由你定），输入 `skeletons.json` + 本项目 `scored.json` + 本项目现有 driver 序列，输出三份 `plan_*.json`。

### 7.1 focus

骨架取**本项目已有 driver 的真实序列**，往里插未调用过的 API。两条插入规则：

**规则 1 —— 插 configure**：角色 = `configure` + handle 类型与序列中已有 API 一致 + 从未被调用。判据是「同一个 handle 上的 set 操作会改变后续行为」。handle 类型从签名首参提取。

**规则 2 —— 换同角色的替代实现**：角色相同 + handle 一致 + 从未被调用。例：libpng 现有 driver 用 `png_read_png`（整图解码），`png_read_row`（逐行解码）从没被调过，是同一 `process` 槽的另一条实现路径，走的代码完全不同。

规则 2 有个**结构性陷阱**：替代实现常带前置依赖（`png_read_row` 需要先 `png_read_info` + `png_start_read_image`），而这些前置 API 若也从没被调用过，图谱里就没有共现记录，依赖关系推不出来。

处理：

- **有依赖证据才用**：本项目其它 driver 里出现过这条链，且共现次数 ≥3、顺序一致率 ≥90%
- **没证据时不要硬上**。未初始化崩溃编译期查不出来，step3 的构建修复循环兜不住，只会表现为覆盖率接近零
- 没证据但仍要生成时，`prerequisite` 字段标 `"inferred_by_llm"`，把风险显式记下来
- 更好的处理：**没证据的直接交给 peer**。若本项目没有逐行解码 driver 但骨架池里有这个形状，那本来就是一条本项目缺失的骨架，前置链在别的项目 driver 里完整可见

依赖证据的查询：Q9 现在是纯共现计数（`count(DISTINCT d)` 按 freq 排），**不含顺序**【已验证】。CALLS 边现在有 `order_last`，改查询即可同时拿到共现次数和顺序一致率，正好对上上面两条判据。

**focus 的候选排序**：本项目每个未调用的 configure 类 API 都能插，候选常有几十上百个，`--num-drivers=N` 是上限。建议**按 handle 类型分组、每组取一个**——focus 的目标是挖深度，N 个 driver 全动同一个 handle 等于只挖了一条路径。

### 7.2 peer 与 cross

按 2.4 的结构距离分档。两者的**生成逻辑完全相同**，只有候选骨架的距离区间不同：

```
候选骨架 = 骨架池中 d(k) == 2（peer）或 d(k) >= 3（cross）
按 support_drivers 降序
对每条骨架，逐槽在本项目 API 池里找对应角色的候选
  填不满任何一个槽 → 整条跳过，记入 skipped
取前 N 条
```

**槽位填充的角色判据**：

- **C 项目**：签名规则可作为快速筛选，但**低召回**——实测在 libarchive 的未调用 API 池上只命中 19%（574 中 110，逐角色 data_sink 57 / configure 34 / create 19）。所以规则命中的直接采信，**未命中的必须过 LLM**，不能直接排除
- **C++ 方法：一律过 LLM，不用签名规则**【已验证】。C++ 签名形如 `bool PcapNgFileWriterDevice::writePacket(const pcpp::RawPacket&, const std::string&)`，参数用引用不是指针、返回值常是引用或值、`this` 隐含（`Logger::suppressLogs(void)` 的 `param_count=0` 但实际作用在对象上），四条签名规则全线失效

**范例给不给**：

- focus 给本项目源码
- peer 给同场景源码
- **cross 不给源码范例**——会误导 LLM 臆造不存在的 API

**语料污染警告**【已验证】：`/root/gyx/projects/` 下 `c-blosc2/` 混有 zlib 的 driver，`gnutls/` 和 `uwebsockets/` 混有 BoringSSL 的。取范例前必须清理。

### 7.3 闸门 2：生成前的统计检查

**三份 plan 生成后，先只看统计，不要跑 LLM 生成。** 这一步几乎零成本（不烧 GPU、不跑 docker），能在浪费 30 次 docker 构建之前发现问题。

判据：

- cross 平均每项目产出 ≥ 3 条
- **且** 达到 ≥3 条的项目数 ≥ 6/10

只过平均不过分布，说明 cross 只对特定项目有效——那本身是个结论，但不足以支撑全量实验。

同时看 `skipped` 的分布：如果跳过率很高，问题在槽位填充而不在设计。

---

## 8. Phase B：step2 大改

**【自行定位】** 本文作者没读过 `step2_generate.py` 的主体，以下只给目标状态和保留/删除清单。

### 8.1 删除

- `pre_allocate_domains`
- `design_call_sequence`
- `group_by_domain`
- `DOMAIN_PREFIX_RULES`
- `ensure_domain_groups` / `classify_domains_llm`（在 `step2_generate.py:605` 附近）【已验证位置】

### 8.2 保留

- `build_signature_cache` / `lookup_signatures`
- 三个校验器
- LLM 调用与重试逻辑

### 8.3 改写

`build_prompt` 改为**读 plan 填骨架槽位**。prompt 结构：

```
骨架序列（角色名 + 每槽 fill_count）
  ↓
每槽的候选 API（名字 + 签名 + 头文件）
  ↓
范例（focus 给本项目源码 / peer 给同场景 / cross 不给）
  ↓
生成要求
```

### 8.4 `ensure_domain_groups` 的三个反面教材

如果要写新的 LLM 批量调用（比如 role 标注脚本），**不要照抄它**【已验证】：

1. **它不分批**——把 `scored_apis` 全集拼进一个 prompt 一次发出。3000 个 API 塞不下，且长 prompt 分类质量明显下降。新代码必须真分批
2. **缓存是单文件 all-or-nothing**（`domain_groups.json`），中途失败全丢。新代码要逐条缓存，key 用 `name + signature + description` 的哈希（**不能只用 name**，不同库同名 API 语义不同）
3. **LLM 漏写的项被静默丢弃**——`cleaned` 只保留 LLM 返回且在 `valid_names` 里的名字。在领域分组里无所谓（有前缀规则兜底），但在角色标注里是致命的：漏标会让 API 在序列里凭空消失、形状改变，而 unknown 处理规则根本不会触发。**新代码必须做返回完整性校验：发出去 N 个，收回来必须是 N 个，缺的强制补 `unknown` 并记日志**

值得借用的只有两样：`_extract_json_obj`（容忍 ```json 围栏和前后杂字，这个实现踩过坑）和两级模型兜底（fast → strong）的调用模式。

---

## 9. 实验与验收

### 9.1 主指标：union-vs-k 曲线

**不要用「总覆盖行数」作主指标**，它随 driver 数单调增，三模式产出数量不同时不可比。

```
对每个模式，随机抽 k 个 driver 求覆盖并集，多次取平均，k = 1..N
四条曲线画一张图：origin / focus / peer / cross
```

- 对比点取 **k = min(N) − 1**。若在 k = min(N) 处比，产出最少的模式只有一种组合（C(3,3)=1），是单次实现无法平均，而产出多的模式有分布——恰好是最需要辩护的那条曲线拿到最不稳的点
- 能抽样的画均值 ± 标准差，不能抽样的标单点并注明
- **origin 必须画进同一张图**。它能直接回答「5 个生成的 driver 能不能打过 5 个人写的 driver」，自动消解「你不就是多写了几个 driver 吗」的质疑
- profraw 按 target 存，这条曲线**不用重跑任何回放**，只是多跑几次 merge，成本几乎为零

### 9.2 报表

副指标报各模式满 N 的总覆盖量，并显式标注 N 和机时。

跑不了某个模式的项目（0 driver 项目跑不了 focus 和 origin；`qpid-proton` 这类自有形状太少的跑不了 peer）用 **`n/a` 而非空白或 0**——空白在结果表里看起来像失败，其实是不适用。这类项目建议单独成表，并说明「这是三模式里唯一能覆盖冷启动项目的证据」。

### 9.3 预期结果与解释

**预期 peer ≈ cross。** 实测跨场景形状迁移性与同场景相当甚至更好，这是设计的已知性质，不是缺陷。论文里应把它报成发现（「fuzz driver 的调用形状是跨场景通用的」），而不是失败。改用结构距离分档后，两个模式的差异变成「结构远近」，这个差异有数据支撑。

---

## 10. 执行顺序

```
1. Phase A 全部（config / run_pipeline / step3 隔离 / plan loader + 夹具）
2. P0 三条缺陷（先验证再修，特别是 tool_grep_symbol）
3. 数据契约三份 JSON 的 schema + loader 定死
4. 读 step2_generate.py 的 build_prompt 与三个校验器，报告实际结构
5. Section E（focus / peer / cross 的 plan 生成）
6. 闸门 2：三份 plan 只看统计，不跑生成 —— 未过则停下来报告
7. step2 大改
8. P1 缺陷
9. 全量实验
10. P2 缺陷（可延后到实验之后）
```

**第 6 步是硬闸门。** 不要跳过它直接跑生成。

---

## 附录：还没做完的事

以下是本文作者知道但没有完成的，不要当成已解决：

1. **角色标注只覆盖了 2 个场景**（CompressionArchive 276 个 API、NetworkProtocol 479 个），且是人工标注不是 LLM 标注。生产管线要用 LLM 标全部 3,055 个有 `order` 边的 API，**LLM 标注与人工标注的一致性没有验证过**——上面所有形状数字都建立在人工标注上
2. **骨架池只有 55 条**（两场景合并）。全部 9 个正常档场景挖完后会更大，2.4 的距离分档阈值可能需要重新校准
3. **富化率两极分化**：全图 74% 有签名，但按项目看是两极分化——`binutils-gdb` 16805 个 API 有 0 个签名，`kcodecs` 19640/67，`glib` 3859/2，`abseil-cpp` 1268/0，另有 `poppler`/`zlib`/`wget`/`gstreamer` 等为 0。选实验项目时避开这批即可，不是阻塞项，但跨结构借骨架时若骨架来自这些项目要谨慎（`source_enrichment_rate` 字段就是为此）
4. **手工验证集未做**：计划在 libarchive 的未调用 API 池（574 个有签名）里手工标 50 个，按签名规则预测的角色分层（data_sink 25 / configure 15 / create 10），用来测签名规则在目标分布上的**准确率**。召回率不用手工测——`skipped` 字段已让召回失败变成运行时可观测
5. **`DataSerialization` 意外掉档**：交接材料里它是第三大场景（86 个有边 driver），按 `order` 口径只剩 39、可用只剩 14。怀疑原因是 JSON/XML 解析类 driver 天然就短（「拿 buffer → parse → free」三步，边数达不到 4）。若属实，正确处理不是排除它，而是对该场景单独把可用门槛降到 ≥3
