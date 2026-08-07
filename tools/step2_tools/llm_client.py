#!/usr/bin/env python3
"""Step2 LLM 客户端：调用 OpenAI 兼容 API + 代码提取/校验。"""
# 从 step2_generate.py 阶段3 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import re

# ─── Phase C: LLM 生成 ─────────────────────────────────────────────
def call_openai_compatible_model(prompt, model, api_key, base_url):
    """调用 OpenAI 兼容 API（DeepSeek 等）——使用 requests，无需 openai SDK。"""
    import time
    import requests as _req

    t0 = time.time()
    url = (base_url.rstrip("/") if base_url else "https://api.deepseek.com") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 32768,   # DeepSeek 推理模式：reasoning_content 占大量 token，需留 content 空间
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an expert C/C++ security engineer specializing in coverage-guided fuzzing and OSS-Fuzz harness development. "
                    "Your task is to generate a production-quality libFuzzer fuzz driver (harness) for an open-source library.\n\n"
                    "A fuzz driver implements `LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)` and feeds the fuzzer-provided "
                    "byte payload into the target library's APIs to maximize code coverage and trigger latent bugs "
                    "(heap-buffer-overflow, use-after-free, integer-overflow, null-dereference, etc.) detectable by "
                    "AddressSanitizer, MemorySanitizer, and UBSan.\n\n"
                    "Requirements:\n"
                    "- Compile cleanly with clang under OSS-Fuzz build flags: -fsanitize=address,fuzzer-no-link\n"
                    "- Exercise the specified API sequence in a realistic call order (init → use → cleanup)\n"
                    "- Handle all error paths: check every pointer return for NULL, every error code for failure\n"
                    "- Free all allocated resources on every exit path to avoid false-positive leak reports\n"
                    "- Never call exit() or abort(); return 0 on all paths\n\n"
                    "Output only the complete C/C++ source code in a single fenced code block. No prose, no explanation."
                ),
            },
            {"role": "user", "content": prompt},
        ],
    }
    try:
        resp = _req.post(url, json=payload, headers=headers, timeout=180)
        elapsed = time.time() - t0
        if resp.status_code != 200:
            print(f"    [{model}] API HTTP {resp.status_code} ({elapsed:.1f}s): {resp.text[:200]}", flush=True)
            return None
        data = resp.json()
        msg = data.get("choices", [{}])[0].get("message", {})
        # DeepSeek 推理模式：content 空 → 取 reasoning_content 兜底
        text = msg.get("content", "") or msg.get("reasoning_content", "") or ""
        if text:
            print(f"    [{model}] API 成功 ({elapsed:.1f}s, {len(text)} chars"
                  + (", via reasoning_content" if not msg.get("content") else "") + ")", flush=True)
            return text
        print(f"    [{model}] API 空响应 ({elapsed:.1f}s)", flush=True)
        return None
    except Exception as e:
        elapsed = time.time() - t0
        print(f"    [{model}] API 异常 ({elapsed:.1f}s): {type(e).__name__}: {str(e)[:200]}", flush=True)
        return None


def call_llm(prompt, model, api_key, base_url, provider):
    """调用 LLM（当前仅支持 OpenAI 兼容接口）。"""
    return call_openai_compatible_model(prompt, model, api_key, base_url)


def extract_code(response_text):
    """从 LLM 响应中提取 C 代码"""
    m = re.search(r'```c\n(.*?)\n```', response_text, re.DOTALL)
    if not m:
        m = re.search(r'```cpp\n(.*?)\n```', response_text, re.DOTALL)
    if not m:
        m = re.search(r'```\n(.*?)\n```', response_text, re.DOTALL)
    if m:
        return m.group(1).strip()
    if '```c' in response_text or '```cpp' in response_text or '```' in response_text:
        return None
    if 'LLVMFuzzerTestOneInput' in response_text:
        return response_text.strip()
    return None


def is_valid_driver(code):
    """检查生成的 driver 是否完整"""
    if not code or len(code) < 80:
        return False
    if 'LLVMFuzzerTestOneInput' not in code:
        return False
    if '```c' in code or '```cpp' in code or '```' in code:
        return False
    if code.count('{') != code.count('}'):
        return False
    last_lines = code.strip().rsplit('\n', 5)
    last_content = '\n'.join(last_lines)
    if 'return 0' not in last_content and 'return' not in last_content:
        return False
    if code.startswith('{') or code.startswith('```json'):
        return False
    bad_starts = ['here', 'sure', 'i\'ll', 'i will', 'let me', 'below', 'the following']
    first_word = code.strip().split()[0].lower() if code.strip().split() else ''
    if first_word in bad_starts:
        return False
    return True
