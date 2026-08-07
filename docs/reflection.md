# 深度反思记录（2026-08-06）

通篇过代码带思考发现的问题。**先记录，等允许再修。**

## 重要 bug

### #1 plan_gen.py:67 `_llm_fill_missing_roles` 的 strong 兜底失效

**位置**：`tools/step2_tools/plan_gen.py` line 67-72

**问题**：
```python
results = _annotate_batch(batch, FAST_MODEL)
if len(results) < len(batch):  # ← 永远 False
    missing_apis = {e["api"] for e in batch} - {r["api"] for r in results}
    retry = [e for e in batch if e["api"] in missing_apis]
    results2 = _annotate_batch(retry, STRONG_MODEL)
    results.extend(results2)
```

`_annotate_batch` 内部已做完整性校验（缺的补 unknown + incomplete 标记），返回长度**恒等于** len(batch)。所以 `len(results) < len(batch)` 永远 False，strong 兜底永远不触发。

**影响**：fast 模型 incomplete 的 API 不会被 strong 重跑，role 标注质量降低（incomplete 的标 unknown 留在 role_labels 里）。

**修法**：改成 `if any(r.get("incomplete") for r in results):` 判断，对 incomplete 的用 strong 重跑。

## 小问题（文档/一致性）

### #2 step2 _run_peer_cross_mode docstring 过时

**位置**：`step2_generate.py` line 2017-2018

- 说 "L2/L3 拦截" 但实际 L2 已改成警告（line 2000）
- 说 "output/<project>/<mode>/" 但实际改成 `output/<project>/driver/<mode>/`（output_for 改了）

**修法**：更新 docstring。

### #3 _llm_fill_missing_roles docstring 与实际不一致

**位置**：`tools/step2_tools/plan_gen.py` line 44

docstring 说"缓存 key = hash(name+signature+description)"，但 plan_gen 的 `_load_role_labels` 用 api 名做 key（项目内 api 名唯一，功能 OK，但文档说 cache_key 不一致）。

**修法**：docstring 改成"role_labels.jsonl 按 (project, api) 索引，项目内 api 名唯一"。

## 未修（用户同意先放着）

### #4 P1 #6 run_api_scoring dependencies/peers 硬编码

**位置**：`step1_prepare.py` line 890-891

```python
"total_score": max(total, 0), "peers": [],
"existing_drivers": tested_map.get(name, []), "dependencies": [],
```

setup.json 的 api_dependencies 未接入 scored。用户说"在实现 focus 规则2 的依赖证据检查时变成前置——那需要 Q9 加顺序一致率（共现次数 ≥3 且顺序一致率 ≥90%），到时候一起做"。

### #5 Q7 scope 改了但没验证数量变化

**位置**：`step1_prepare.py` line 162（已改 d 绑定 `(lib)-[:HAS_DRIVER]->(d)`）

用户要求"改完在一个项目上报 untested_apis 的数量变化"。当前改了但没跑 step1 验证 untested 数量变化（要 Neo4j 连接）。

## 设计选择（非 bug）

### #6 fuzz_runner corpus_dir 临时

`run_one_fuzzer` 的 corpus_dir 是 `tempfile.mkdtemp`，跑完 `shutil.rmtree`。libFuzzer 发现的新 corpus 丢了。当前是"跑一轮看 crash"不需要累积，但如果要长期 fuzz 累积 corpus，要持久化 corpus_dir。

### #7 agent_pipeline DC_OFFICIAL_RC 判断在 round 1 后

`if failed and official_rc != 0 and r >= 1` —— round 0（第一轮）官方构建失败仍进修复循环。保守做法（给第一轮机会），但可能空耗。P1 #4 的意图是"官方构建失败→修复空耗→跳过"，round 0 就该跳更激进。

## 待验证（需跑实验确认）

### #8 relabel_data_sink 后 role_labels.jsonl 有无重复条目

`_llm_fill_missing_roles` 追加写 role_labels.jsonl。如果同一个 (project, api) 被标注两次（第一次 plan_gen 跑标了，第二次又标），会追加重复条目。load 时后者覆盖前者（最新），但 count 偏多。要检查 role_labels.jsonl 有无重复 (project, api)。

### #9 skeleton_mine 的 _load_role_labels 重复条目处理

同 #8，skeleton_mine 加载 role_labels.jsonl 时 `labels[(proj, api)] = role`，后者覆盖前者。如果有重复条目，count 偏多但逻辑正确（用最新）。可加 dedup 日志。
