"""tools.step3_agent 包 —— 多 Agent 编译修复循环（agent_common/main/pipeline/triage/build_fix/repair）。

包位置：driver_create/tools/step3_agent/（原根目录 agent/，阶段1c 搬入）。

import 约定：包内模块互相引用一律用绝对包形式
（`from tools.step3_agent import agent_common as ac`、
`from tools.step3_agent.agent_repair import tool_grep_symbol` 等）；
`from config import ...` 靠根目录在 sys.path。

本 __init__ 在包被加载时把根目录插进 sys.path 作直接执行兜底（正常以
`python3 -m tools.step3_agent.<模块>` 或从根 `from tools.step3_agent import ...`
调用时根目录已由 cwd 提供，此插入冗余但无害）。
"""

import sys as _sys
from pathlib import Path as _Path

_PKG_DIR = _Path(__file__).resolve().parent          # …/driver_create/tools/step3_agent
_ROOT_DIR = _PKG_DIR.parent.parent                   # …/driver_create

for _p in (str(_PKG_DIR), str(_ROOT_DIR)):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
