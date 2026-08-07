#!/usr/bin/env python3
"""
relabel_data_sink.py — 只重标当前 role=="data_sink" 的 API（收紧判据）

背景：LLM 过度使用 data_sink（27% 准确率），57 个 process 被标成 data_sink。
责任在判据歧义——"既收字节又干活"的一次性函数（ZSTD_decompress）。

收紧判据：
  data_sink：调用返回后对象「持有了输入、等待后续处理」（如 archive_read_open_memory）
  process：调用返回后活已经干完了（如 ZSTD_decompress、parse_msg）
  configure：字典/配置类 const void* + size（如 ZSTD_CCtx_loadDictionary）不是 fuzz 输入

只重标 role=="data_sink" 的 213 个，其余 6 角色不动。
按项目分批（防同名跨项目错位），完整性校验（发 N 收 N，缺补原 data_sink）。
结果覆盖写回 role_labels.jsonl。
"""
import sys
import json
import hashlib
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config import shared_dir, DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_FAST_MODEL
import requests as _req

LABELS_FILE = shared_dir() / "role_labels.jsonl"
BATCH_SIZE = 40

SYSTEM_PROMPT = """你是 C/C++ 库 API 角色标注专家。判断下列 API 是 data_sink 还是 process（或其他角色）。

收紧判据（关键区分）：
- data_sink：调用返回后，对象「持有了输入、等待后续处理」——数据进对象后还要后续调用才完成
  正例：archive_read_open_memory（打开后还要 next_header + read_data）、spng_set_png_stream、ofpbuf_use_const、ZSTD_seekable_initBuff
- process：调用返回后，活已经干完了——既收字节又把活一次性干完
  正例：ZSTD_decompress、blosc2_decompress、parse_msg、archive_read_data、plist_from_xml
- configure：字典/配置类 const void* + size（如 ZSTD_CCtx_loadDictionary）不是 fuzz 输入，标 configure
- destroy：释放/关闭对象（free/destroy/close）
- create：工厂函数返回新对象
- query：只读不改状态

对每个条目返回 {"idx": 序号, "role": "角色", "reason": "一句话"}。
role 只能是：create/configure/data_sink/process/destroy/query/unknown。
返回 JSON 数组，发 N 个必须收 N 个，idx 与输入序号对应。"""

USER_TEMPLATE = """请标注以下 {n} 个 API 的角色（重点区分 data_sink vs process）：

{entries}

返回 JSON 数组，每个元素 {{"idx", "role", "reason"}}，idx 与上方序号对应。"""


def _cache_key(api_entry):
    return hashlib.md5(
        (api_entry.get("api", "") + "|" + api_entry.get("signature", "")
         + "|" + api_entry.get("description", "")).encode()
    ).hexdigest()


def _call_llm(prompt, model):
    if not DEEPSEEK_API_KEY:
        return None
    url = (DEEPSEEK_BASE_URL or "https://api.deepseek.com").rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "max_tokens": 8192,
        "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": prompt}],
        "temperature": 0.1,
    }
    try:
        resp = _req.post(url, json=payload, headers=headers, timeout=120)
        if resp.status_code != 200:
            print(f"    [llm] HTTP {resp.status_code}: {resp.text[:200]}")
            return None
        return resp.json().get("choices", [{}])[0].get("message", {}).get("content") or ""
    except Exception as e:
        print(f"    [llm] 调用失败: {e}")
        return None


def _extract_json(text):
    import re
    m = re.search(r'\[\s*\{.*?\}\s*\]', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(text.strip().strip('`').replace("json\n", "", 1))
    except Exception:
        return None


def _annotate_batch(batch, model):
    """标注一批，完整性校验（按 idx 对齐，发 N 收 N，缺补原 data_sink）。"""
    entries = "\n".join(
        f"{i+1}. [idx={i+1}] {e['api']}  sig={e.get('signature','')}  desc={e.get('description','')}"
        for i, e in enumerate(batch)
    )
    prompt = USER_TEMPLATE.format(n=len(batch), entries=entries)
    text = _call_llm(prompt, model)
    if not text:
        return []
    obj = _extract_json(text)
    if not isinstance(obj, list):
        return []
    # 按 idx 对齐（防跨项目同名错位）
    by_idx = {}
    for r in obj:
        if isinstance(r, dict) and r.get("idx"):
            by_idx[int(r["idx"])] = r
    valid_roles = {"create", "configure", "data_sink", "process", "destroy", "query", "unknown"}
    results = []
    for i, e in enumerate(batch):
        r = by_idx.get(i + 1)
        if r and r.get("role") in valid_roles:
            results.append({**e, "role": r["role"],
                           "reason": (r.get("reason") or "")[:200], "model": model})
        else:
            # 缺的或角色非法 → 保留原 data_sink（不凭空消失）
            results.append({**e, "role": "data_sink",
                           "reason": "[relabel_incomplete] LLM 未返回，保留原 data_sink",
                           "model": model, "incomplete": True})
    return results


def main():
    # 1. 读全量 role_labels.jsonl
    all_records = []
    with open(LABELS_FILE, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                all_records.append(json.loads(line))
    print(f"[relabel] 全量 {len(all_records)} 条")

    # 2. 筛 role=="data_sink" 的
    data_sink_indices = [i for i, r in enumerate(all_records) if r.get("role") == "data_sink"]
    print(f"[relabel] data_sink: {len(data_sink_indices)} 个，重标")

    # 3. 合并大批（不分项目，用 idx 对齐防跨项目同名错位）
    data_sink_entries = [all_records[i] for i in data_sink_indices]
    print(f"[relabel] 合并 {len(data_sink_entries)} 个，分批 {BATCH_SIZE}/批（idx 对齐，并行）")

    # 4. 分批并行调 LLM（6-way parallel，DeepSeek 支持并发）
    fast = DEEPSEEK_FAST_MODEL or "deepseek-v4-flash"
    strong = DEEPSEEK_MODEL or "deepseek-v4-pro"
    batches = []
    for bi in range(0, len(data_sink_entries), BATCH_SIZE):
        batch = data_sink_entries[bi: bi + BATCH_SIZE]
        batches.append((bi // BATCH_SIZE + 1, batch))

    from concurrent.futures import ThreadPoolExecutor, as_completed
    new_roles = {}  # id(api_entry) → new role record

    def _run_batch(bidx, batch):
        batch_ids = [id(e) for e in batch]
        results = _annotate_batch(batch, fast)
        incomplete_idx = [i for i, r in enumerate(results) if r.get("incomplete")]
        if incomplete_idx:
            retry = [batch[i] for i in incomplete_idx]
            results2 = _annotate_batch(retry, strong)
            results = [r for i, r in enumerate(results) if i not in incomplete_idx]
            for j, r2 in enumerate(results2):
                results.insert(incomplete_idx[j], r2)
        return bidx, batch_ids, results

    max_workers = min(len(batches), 6)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_run_batch, bidx, batch): bidx for bidx, batch in batches}
        for fut in as_completed(futures):
            bidx, batch_ids, results = fut.result()
            for j, r in enumerate(results):
                new_roles[batch_ids[j]] = r
            print(f"  batch {bidx}/{len(batches)}: {len(results)} 个标注")

    # 5. 覆盖写回 role_labels.jsonl（只改 213 个 data_sink 的 role）
    changed = 0
    for idx in data_sink_indices:
        r = all_records[idx]
        nr = new_roles.get(id(r))
        if nr:
            if nr["role"] != "data_sink":
                changed += 1
            r["role"] = nr["role"]
            r["reason"] = nr.get("reason", r.get("reason", ""))
            r["model"] = nr.get("model", r.get("model", ""))
            r["relabel_ts"] = "20260806"

    with open(LABELS_FILE, "w", encoding="utf-8") as f:
        for r in all_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # 统计变化
    from collections import Counter
    before = Counter(all_records[i].get("role") for i in data_sink_indices)
    after = Counter(all_records[i].get("role") for i in data_sink_indices)
    print(f"\n[relabel] 完成：{changed} 个从 data_sink 改成其他角色")
    print(f"  data_sink: {before['data_sink']} → {after['data_sink']}")
    for role in ("process", "configure", "create", "destroy", "query", "unknown"):
        if after[role] > 0:
            print(f"  → {role}: {after[role]}")


if __name__ == "__main__":
    main()
