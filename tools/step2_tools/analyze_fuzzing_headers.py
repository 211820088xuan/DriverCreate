#!/usr/bin/env python3
"""
分析项目已有 fuzzer 的头文件使用模式，识别必须 include 的 fuzzing 基础设施头文件。

三种模式：
- 模式 A：项目自带 fuzzing 基础设施（如 fuzzer.h、fuzzer-common.h）
- 模式 B：OSS-Fuzz 特定构建依赖（如 common.h，FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION）
- 模式 C：混合模式（部分项目工具、部分测试框架）
"""

import os
import re
import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import Counter

# tools/ 下的脚本用 sys.path bootstrap 引用根目录 config
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# 目录常量统一从 config 取（避免与 config.py 重复定义、并自动适配 source_code/ 与 artifacts/ 改名）
from config import PROJECTS_DIR, SRC_DIR, INTERMEDIATE_DIR


def extract_includes_from_file(file_path: Path) -> List[str]:
    """从单个源文件中提取所有 #include 语句"""
    includes = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # 匹配 #include "..." 或 #include <...>
                match = re.match(r'^\s*#include\s+[<"]([^>"]+)[>"]', line)
                if match:
                    includes.append(match.group(1))
    except Exception as e:
        print(f"    [warn] 无法读取 {file_path}: {e}")
    return includes


def scan_project_fuzzers(project: str) -> Tuple[List[Path], Dict[str, int]]:
    """
    扫描项目的已有 fuzzer，统计头文件使用频率

    Returns:
        (fuzzer_files, header_counts): fuzzer 文件列表和头文件计数
    """
    project_dir = PROJECTS_DIR / project
    if not project_dir.exists():
        return [], {}

    # 扫描所有 C/C++ fuzzer 文件
    fuzzer_files = []
    for ext in ['*.c', '*.cc', '*.cpp', '*.cxx']:
        fuzzer_files.extend(project_dir.glob(ext))

    if not fuzzer_files:
        return [], {}

    # 统计头文件出现次数
    header_counter = Counter()
    for fuzz_file in fuzzer_files:
        includes = extract_includes_from_file(fuzz_file)
        header_counter.update(includes)

    return fuzzer_files, dict(header_counter)


def check_header_location(project: str, header: str) -> Dict[str, any]:
    """
    检查头文件的位置和内容

    Returns:
        {
            "exists_in_source": bool,
            "source_path": str or None,
            "content_preview": str or None (前200行)
        }
    """
    result = {
        "exists_in_source": False,
        "source_path": None,
        "content_preview": None
    }

    src_project_dir = SRC_DIR / project
    if not src_project_dir.exists():
        return result

    # 尝试在源码中查找头文件
    # 1. 直接路径
    direct_path = src_project_dir / header
    if direct_path.exists():
        result["exists_in_source"] = True
        result["source_path"] = str(direct_path.relative_to(src_project_dir))
        result["content_preview"] = _read_file_preview(direct_path, max_lines=200)
        return result

    # 2. 在常见目录中搜索
    search_dirs = ["include", "src", "lib", "oss-fuzz", "fuzz", "test", "tests",
                   "fuzzing", "contrib", "programs"]
    filename = Path(header).name

    for search_dir in search_dirs:
        search_path = src_project_dir / search_dir
        if search_path.exists():
            # 递归查找
            for found in search_path.rglob(filename):
                if found.is_file():
                    result["exists_in_source"] = True
                    result["source_path"] = str(found.relative_to(src_project_dir))
                    result["content_preview"] = _read_file_preview(found, max_lines=200)
                    return result

    # 3. Fallback: 全源码树搜索
    for found in src_project_dir.rglob(filename):
        if found.is_file():
            result["exists_in_source"] = True
            result["source_path"] = str(found.relative_to(src_project_dir))
            result["content_preview"] = _read_file_preview(found, max_lines=200)
            return result

    return result


def _read_file_preview(file_path: Path, max_lines: int = 200) -> str:
    """读取文件前 N 行作为预览"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    lines.append(f"... (truncated at {max_lines} lines)")
                    break
                lines.append(line.rstrip())
            return '\n'.join(lines)
    except Exception as e:
        return f"[Error reading file: {e}]"


def analyze_headers_with_agent(
    project: str,
    fuzzer_count: int,
    header_stats: List[Dict],
    max_steps: int = 10
) -> Optional[Dict]:
    """
    使用 agent 分析头文件模式

    Args:
        project: 项目名
        fuzzer_count: fuzzer 总数
        header_stats: 头文件统计信息列表
        max_steps: agent 最大步数

    Returns:
        分析结果 JSON 或 None
    """
    try:
        import requests as _req
        from config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL
    except ImportError as e:
        print(f"  [error] 无法导入依赖: {e}")
        return None

    # 构建 system prompt
    system_prompt = f"""你是一个 fuzzing 基础设施分析专家。你的任务是分析项目 {project} 的已有 fuzzer 使用的头文件，判断哪些是必须 include 的 fuzzing 基础设施头文件。

## 三种头文件模式

**模式 A：项目自带 fuzzing 基础设施**
- 项目源码中维护的 fuzzer helper 头文件
- 例如：fuzzer.h, fuzzer-common.h, test_utils.h
- 特征：存在于项目源码 src/<project>/ 中，提供通用初始化、工具函数等

**模式 B：OSS-Fuzz 特定构建依赖**
- 只在 OSS-Fuzz 构建环境中存在的头文件
- 例如：common.h（包含 FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION、alloc_check_threshold 等测试变量）
- 特征：不在项目源码中，或只在 FUZZING_BUILD_MODE 下编译

**模式 C：混合模式**
- 部分是项目工具，部分是测试框架
- 需要根据具体内容判断

## 你的任务

分析提供的头文件使用统计，判断：
1. 哪些头文件属于 fuzzing 基础设施（模式 A/B/C）
2. 哪些是必须 include 的（高频使用 + 非标准库）
3. 哪些是项目公开 API（不需要特殊标记）

## 输出格式

使用 submit_analysis 工具提交结果，格式：
{{
  "required_headers": [
    {{"path": "common.h", "pattern": "B", "reason": "OSS-Fuzz测试变量，8/8 fuzzer使用"}},
    {{"path": "fuzzer.h", "pattern": "A", "reason": "项目自带fuzzer工具，6/8使用"}}
  ],
  "optional_headers": [
    {{"path": "test_helper.h", "pattern": "A", "reason": "仅2/8使用，非必须"}}
  ],
  "standard_or_api_headers": [
    "FLAC++/decoder.h",  // 项目公开API
    "cstdint"  // 标准库
  ]
}}

## 判断标准

- **必须 (required)**：使用频率 ≥ 50% 且属于 fuzzing 基础设施（模式 A/B/C）
- **可选 (optional)**：使用频率 < 50% 但仍属于 fuzzing 基础设施
- **标准/API (standard_or_api)**：标准库头文件或项目公开 API

"""

    # 构建工具定义
    tools = [
        {
            "type": "function",
            "function": {
                "name": "submit_analysis",
                "description": "提交头文件分析结果",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "required_headers": {
                            "type": "array",
                            "description": "必须 include 的 fuzzing 基础设施头文件",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "pattern": {"type": "string", "enum": ["A", "B", "C"]},
                                    "reason": {"type": "string"}
                                },
                                "required": ["path", "pattern", "reason"]
                            }
                        },
                        "optional_headers": {
                            "type": "array",
                            "description": "可选的 fuzzing 基础设施头文件",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                    "pattern": {"type": "string", "enum": ["A", "B", "C"]},
                                    "reason": {"type": "string"}
                                },
                                "required": ["path", "pattern", "reason"]
                            }
                        },
                        "standard_or_api_headers": {
                            "type": "array",
                            "description": "标准库或项目公开 API 头文件",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["required_headers", "optional_headers", "standard_or_api_headers"]
                }
            }
        }
    ]

    # 构建初始消息
    header_summary = f"项目 {project} 共有 {fuzzer_count} 个 fuzzer。头文件使用统计：\n\n"
    for hs in header_stats:
        header_summary += f"## {hs['header']} ({hs['count']}/{fuzzer_count} 使用, {hs['usage_rate']:.1%})\n"
        header_summary += f"- 存在于源码: {hs['exists_in_source']}\n"
        if hs['source_path']:
            header_summary += f"- 源码路径: {hs['source_path']}\n"
        if hs['content_preview']:
            header_summary += f"- 内容预览:\n```\n{hs['content_preview'][:500]}\n```\n"
        header_summary += "\n"

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": header_summary}
    ]

    # Agent loop
    for step in range(max_steps):
        try:
            response = _req.post(
                f"{DEEPSEEK_BASE_URL}/chat/completions",
                headers={
                    "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": DEEPSEEK_MODEL,
                    "messages": messages,
                    "tools": tools,
                    "max_tokens": 16384,
                    "temperature": 0.7
                },
                timeout=120
            )
            response.raise_for_status()
            data = response.json()

            choice = data["choices"][0]
            message = choice["message"]

            # 添加 assistant 消息
            messages.append(message)

            # 检查是否有工具调用
            if message.get("tool_calls"):
                for tool_call in message["tool_calls"]:
                    func_name = tool_call["function"]["name"]
                    args_str = tool_call["function"]["arguments"]
                    args = json.loads(args_str)

                    if func_name == "submit_analysis":
                        print(f"  [agent] 分析完成，提交结果")
                        return args

            # 检查是否结束
            if choice["finish_reason"] == "stop":
                print(f"  [agent] 结束但未提交，步数: {step+1}")
                return None

        except Exception as e:
            print(f"  [agent] 步骤 {step+1} 异常: {e}")
            return None

    print(f"  [agent] 达到最大步数 {max_steps}")
    return None


def analyze_project_fuzzing_headers(project: str) -> Optional[Dict]:
    """
    分析项目的 fuzzing 头文件模式

    Returns:
        分析结果或 None
    """
    print(f"  分析项目 {project} 的 fuzzing 头文件...")

    # 1. 扫描 fuzzer 文件
    fuzzer_files, header_counts = scan_project_fuzzers(project)
    if not fuzzer_files:
        print(f"    [warn] 未找到 fuzzer 文件")
        return None

    print(f"    找到 {len(fuzzer_files)} 个 fuzzer")
    print(f"    统计到 {len(header_counts)} 个不同的头文件")

    # 2. 计算使用频率阈值，对高频头文件进行详细分析
    fuzzer_count = len(fuzzer_files)
    high_freq_threshold = 0.3  # 30% 以上视为高频

    header_stats = []
    for header, count in sorted(header_counts.items(), key=lambda x: -x[1]):
        usage_rate = count / fuzzer_count

        # 只对高频头文件或 fuzzing 相关路径的头文件做详细分析
        should_analyze = (
            usage_rate >= high_freq_threshold or
            any(kw in header.lower() for kw in ['fuzz', 'test', 'common', 'helper', 'util'])
        )

        if should_analyze:
            location_info = check_header_location(project, header)
            header_stats.append({
                "header": header,
                "count": count,
                "usage_rate": usage_rate,
                "exists_in_source": location_info["exists_in_source"],
                "source_path": location_info["source_path"],
                "content_preview": location_info["content_preview"]
            })
        else:
            # 低频且不像 fuzzing 头文件，简单记录
            header_stats.append({
                "header": header,
                "count": count,
                "usage_rate": usage_rate,
                "exists_in_source": False,
                "source_path": None,
                "content_preview": None
            })

    # 3. 使用 agent 分析
    print(f"    调用 agent 分析头文件模式...")
    analysis_result = analyze_headers_with_agent(project, fuzzer_count, header_stats)

    if not analysis_result:
        print(f"    [warn] agent 分析失败，返回原始统计")
        return {
            "fuzzer_count": fuzzer_count,
            "header_stats": header_stats,
            "required_headers": [],
            "optional_headers": [],
            "standard_or_api_headers": []
        }

    # 4. 合并结果
    result = {
        "fuzzer_count": fuzzer_count,
        "header_stats": header_stats,
        **analysis_result
    }

    return result


def save_analysis_result(project: str, result: Dict) -> Path:
    """保存分析结果到 intermediate/<project>/fuzzing_headers.json"""
    output_dir = INTERMEDIATE_DIR / project
    output_dir.mkdir(parents=True, exist_ok=True)

    output_file = output_dir / "fuzzing_headers.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"    保存分析结果到 {output_file}")
    return output_file


def main():
    """命令行入口"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python3 analyze_fuzzing_headers.py <project>")
        sys.exit(1)

    project = sys.argv[1]

    result = analyze_project_fuzzing_headers(project)
    if result:
        save_analysis_result(project, result)

        # 打印摘要
        print(f"\n  === 分析结果摘要 ===")
        print(f"  必须 include: {len(result['required_headers'])} 个")
        for h in result['required_headers']:
            print(f"    - {h['path']} (模式 {h['pattern']})")
        print(f"  可选 include: {len(result['optional_headers'])} 个")
        print(f"  标准/API: {len(result['standard_or_api_headers'])} 个")
    else:
        print(f"  分析失败")
        sys.exit(1)


if __name__ == "__main__":
    main()
