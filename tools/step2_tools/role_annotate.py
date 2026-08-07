#!/usr/bin/env python3
"""
role_annotate.py — Phase 5: 用 LLM 给 API 标注角色（create/configure/data_sink/process/destroy/query/unknown）

输入：_shared/role_apis.jsonl（3093 个有 order 边的 API + 富化字段）
输出：_shared/role_labels.jsonl（每行一个 API + role + confidence + reason）

设计要点（避免 §8.4 三个反面教材）：
  1. 分批：每批 ≤ 40 个 API，不让 LLM 一次处理 3000 个（长 prompt 分类质量下降）
  2. 逐条缓存：key = hash(name + signature + description)，中途失败不丢已标部分
  3. 返回完整性校验：发出去 N 个，收回来必须是 N 个，缺的强制补 unknown + 记日志
     （ensure_domain_groups 漏写静默丢弃 → 标注会让 API 在序列里凭空消失）

借 §8.4 唯二可借：_extract_json_obj（容忍 ```json 围栏）+ 两级模型兜底（fast → strong）

无凭证 → 降级：全部标 unknown，仍写盘（skeleton_mine 可用，但骨架质量低）
"""
import sys
import json
import hashlib
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from config import (
    shared_dir, ROLES, ROLE_LABELS_EXTENDED,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_FAST_MODEL,
)
import requests as _req

# ── 路径 ──
IN_FILE = shared_dir() / "role_apis.jsonl"
OUT_FILE = shared_dir() / "role_labels.jsonl"
CACHE_FILE = shared_dir() / "role_labels_cache.jsonl"

# ── 批大小与模型 ──
BATCH_SIZE = 40
FAST_MODEL = DEEPSEEK_FAST_MODEL or "deepseek-v4-flash"
STRONG_MODEL = DEEPSEEK_MODEL or "deepseek-v4-pro"
MAX_RETRIES_PER_BATCH = 2
N_PARALLEL = 6   # 并发批数（DeepSeek 支持并发，6 是兼顾速率限制与吞吐的折中）

# 缓存写锁（多线程并发写 cache 文件）
_cache_lock = threading.Lock()

SYSTEM_PROMPT = """你是 OSS-Fuzz fuzz driver 自动化流水线里的 API 角色标注器。

任务：给每个 API 标注一个角色标签，反映它在 fuzz driver 调用序列里的语义作用。

角色词表（5 个进序列 + 2 个不进）：
- create       让对象从无到可用：分配并返回句柄，或就地初始化（zip_open / mbedtls_ssl_init / ZSTD_createCCtx）
- configure    在已有句柄上设参数、注册回调、启用特性（SSL_CTX_set_max_proto_version / archive_read_support_format_zip）
- data_sink    把外部字节流喂进对象——fuzz 输入的入口（archive_read_open_memory / json_from_string）
               注意：字典/配置类的 const void* + size 参数不是 fuzz 输入，标 configure
- process      业务动作：解析/解码/编码/变换/执行/迭代推进（ZSTD_decompress / archive_read_next_header）
- destroy      释放资源、收尾、关闭（ZSTD_freeCCtx / archive_write_close）
- query        读状态、取属性、查找，不改变对象（不进骨架序列）
- unknown      LLM 无法判定或缺描述（不进骨架序列）

合并规则（已实测，不要拆开）：
- init（返回 void 的就地初始化）并入 create
- iterate 并入 process（边界是项目 API 设计习惯，不是场景结构）
- finalize 并入 destroy
- data_sink 绝不能并入 process——它是 fuzz 输入入口
- data_sink 与 process 重叠时：能直接接收原始字节流的优先标 data_sink

输出格式：JSON 数组，每个元素 {"api": "<名字>", "role": "<标签>", "reason": "<一句话依据>"}
只输出 JSON，不要其它文字。"""

USER_TEMPLATE = """请给以下 {n} 个 API 标注角色。每个 API 给出 {{"api":..., "role":..., "reason":...}}，输出 JSON 数组。

{entries}

要求：
1. 每个必须标一个角色，不能跳过
2. reason 一句话，说明为什么是这个角色（看 signature 的参数/返回值 + description）
3. 输出 JSON 数组，元素数必须等于 {n}
"""


def _extract_json_obj(text: str) -> Optional[object]:
    """从 LLM 响应中健壮提取 JSON（容忍 ```json 围栏和前后杂字）。
    借自 step2_generate._extract_json_obj（§8.4 唯二可借之一）。"""
    if not text:
        return None
    s = text.strip()
    # 去围栏
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s[3:]
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    # 找第一个 { 或 [
    for i, c in enumerate(s):
        if c in "{[":
            start = i
            break
    else:
        return None
    # 找配对的 } 或 ]
    open_c = s[start]
    close_c = "}" if open_c == "{" else "]"
    depth = 0
    end = -1
    for i in range(start, len(s)):
        c = s[i]
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end == -1:
        return None
    try:
        return json.loads(s[start:end])
    except json.JSONDecodeError:
        return None


def _cache_key(api_entry: dict) -> str:
    """逐条缓存 key = hash(name + signature + description)。
    不只用 name——不同库同名 API 语义不同（§8.4 反面教材 2）。"""
    raw = f"{api_entry.get('api', '')}|{api_entry.get('signature', '')}|{api_entry.get('description', '')}"
    return hashlib.md5(raw.encode("utf-8")).hexdigest()


def _load_cache() -> dict[str, dict]:
    """加载已有缓存（逐条 JSONL，中途失败不丢）。"""
    cache: dict[str, dict] = {}
    if CACHE_FILE.is_file():
        for line in CACHE_FILE.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                cache[rec["cache_key"]] = rec
            except (json.JSONDecodeError, KeyError):
                continue
    return cache


def _append_cache(records: list[dict]) -> None:
    """追加写缓存（线程安全，多线程并发写时不交错）。"""
    if not records:
        return
    with _cache_lock:
        with open(CACHE_FILE, "a", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")


def _call_llm(prompt: str, model: str) -> Optional[str]:
    """调用 DeepSeek（OpenAI 兼容），返回文本响应。"""
    if not DEEPSEEK_API_KEY:
        return None
    url = (DEEPSEEK_BASE_URL or "https://api.deepseek.com").rstrip("/") + "/chat/completions"
    headers = {"Authorization": f"Bearer {DEEPSEEK_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "max_tokens": 8192,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,   # 标注要稳，低温度
    }
    try:
        resp = _req.post(url, json=payload, headers=headers, timeout=120)
        if resp.status_code != 200:
            print(f"    [llm] HTTP {resp.status_code}: {resp.text[:200]}")
            return None
        data = resp.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content") or ""
    except Exception as e:
        print(f"    [llm] 调用失败: {e}")
        return None


def _annotate_batch(batch: list[dict], model: str) -> list[dict]:
    """标注一批 API。返回结果列表（每条含 cache_key + role + reason）。
    做完整性校验：发 N 收 N，缺的补 unknown + 标 incomplete。"""
    n = len(batch)
    entries_text = "\n".join(
        f"{i+1}. {e['api']}  sig={e.get('signature','')}  desc={e.get('description','')}"
        for i, e in enumerate(batch)
    )
    prompt = USER_TEMPLATE.format(n=n, entries=entries_text)
    text = _call_llm(prompt, model)
    if not text:
        return []

    obj = _extract_json_obj(text)
    if not isinstance(obj, list):
        return []

    # 完整性校验：按 api 名对齐，缺的补 unknown
    by_api = {r.get("api"): r for r in obj if isinstance(r, dict)}
    results = []
    for e in batch:
        r = by_api.get(e["api"])
        if r and r.get("role") in ROLE_LABELS_EXTENDED:
            results.append({
                "cache_key": _cache_key(e),
                "api": e["api"],
                "project": e.get("project", ""),
                "role": r["role"],
                "reason": (r.get("reason") or "")[:200],
                "model": model,
            })
        else:
            # 缺的或角色非法 → 强制补 unknown（§8.4 反面教材 3：漏标会让 API 凭空消失）
            results.append({
                "cache_key": _cache_key(e),
                "api": e["api"],
                "project": e.get("project", ""),
                "role": "unknown",
                "reason": "[incomplete] LLM 未返回或角色非法，强制补 unknown",
                "model": model,
                "incomplete": True,
            })
    return results


def main():
    if not IN_FILE.is_file():
        sys.exit(f"输入不存在: {IN_FILE}")

    entries = []
    for line in IN_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    print(f"[annotate] 待标注 API: {len(entries)} 个 | 批大小: {BATCH_SIZE}")

    cache = _load_cache()
    print(f"[annotate] 已缓存: {len(cache)} 个")

    if not DEEPSEEK_API_KEY:
        print("[annotate] 无 DEEPSEEK_API_KEY，全部标 unknown 降级写盘")
        results = [{
            "cache_key": _cache_key(e), "api": e["api"], "project": e.get("project", ""),
            "role": "unknown", "reason": "[no_credentials] 降级",
            "model": "none", "incomplete": True,
        } for e in entries]
        _write_output(results)
        return

    # 分批标注，跳过已缓存的
    to_annotate = [e for e in entries if _cache_key(e) not in cache]
    print(f"[annotate] 待标: {len(to_annotate)} | 已缓存跳过: {len(entries) - len(to_annotate)}")

    # 构造批次列表
    batches = []
    for bi in range(0, len(to_annotate), BATCH_SIZE):
        batches.append(to_annotate[bi: bi + BATCH_SIZE])
    n_batches = len(batches)
    print(f"[annotate] {n_batches} 批 × {BATCH_SIZE} API/批，并发 {N_PARALLEL}")

    def _process_batch(idx_batch):
        idx, batch = idx_batch
        # 两级模型兜底：fast 失败 → strong
        results = None
        for attempt in range(MAX_RETRIES_PER_BATCH):
            model = FAST_MODEL if attempt == 0 else STRONG_MODEL
            results = _annotate_batch(batch, model)
            if results and len(results) == len(batch):
                break
            time.sleep(2)
        if not results or len(results) != len(batch):
            results = [{
                "cache_key": _cache_key(e), "api": e["api"], "project": e.get("project", ""),
                "role": "unknown", "reason": "[batch_failed] 两级模型均失败",
                "model": "fallback", "incomplete": True,
            } for e in batch]
            tag = f"batch {idx+1}/{n_batches} FAIL→unknown"
        else:
            n_inc = sum(1 for r in results if r.get("incomplete"))
            tag = f"batch {idx+1}/{n_batches} OK" + (f" ({n_inc} inc)" if n_inc else "")
        _append_cache(results)
        return results

    # 并行跑所有批次
    batch_results: list[dict] = []
    cache_base = len(cache)   # 启动时缓存基数（进度日志用）
    with ThreadPoolExecutor(max_workers=N_PARALLEL) as ex:
        futures = {ex.submit(_process_batch, (i, b)): i for i, b in enumerate(batches)}
        done = 0
        for fut in as_completed(futures):
            done += 1
            try:
                results = fut.result()
                batch_results.extend(results)
                if done % 5 == 0 or done == n_batches:
                    print(f"  [{done}/{n_batches}] 缓存累计: "
                          f"{cache_base + len(batch_results)}")
            except Exception as e:
                print(f"  [batch error] {e}")

    # 合并缓存 + 新结果，写最终输出
    cache.update({r["cache_key"]: r for r in batch_results})
    all_results = [cache[_cache_key(e)] for e in entries if _cache_key(e) in cache]
    _write_output(all_results)

    # 统计
    role_dist = {}
    for r in all_results:
        role_dist[r["role"]] = role_dist.get(r["role"], 0) + 1
    print(f"\n[annotate] 完成: {len(all_results)}/{len(entries)} API 已标注")
    print(f"  角色分布: {role_dist}")
    n_inc = sum(1 for r in all_results if r.get("incomplete"))
    if n_inc:
        print(f"  ⚠️ {n_inc} 个 incomplete（强制补 unknown）")


def _write_output(results: list[dict]) -> None:
    """写最终 role_labels.jsonl。"""
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"[annotate] 输出 → {OUT_FILE}")


if __name__ == "__main__":
    main()
