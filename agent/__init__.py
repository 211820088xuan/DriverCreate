"""agent 包 —— 多 Agent 编译修复循环（agent_common/main/pipeline/triage/build_fix/repair）。

历史背景：这 6 个模块原本平铺在 driver_create/ 根目录，彼此用**绝对 import**
（`import agent_common as ac`、`import agent_main`、`from agent_repair import ...`），
并 `from config import ...` 引用根目录的 config。重组时它们被收进本 `agent/` 包，
为**保持这些 import 零改动**（改动面最小、最不易出错），本 __init__ 在包被加载时
把两条路径插进 sys.path：

  1. 本包目录（agent/）      → 让 `import agent_common` / `import agent_main` 等解析到同目录兄弟模块；
  2. 上一级（driver_create/）→ 让 `from config import ...` 解析到根目录的 config.py。

因此两种调用方式都能跑：
  - `python3 -m agent.agent_pipeline <project>`（推荐，包形式）；
  - 直接 import 本包（如根目录 step3_build.py 的 `from agent import agent_main`）也会触发本 bootstrap。
"""

import sys as _sys
from pathlib import Path as _Path

_PKG_DIR = _Path(__file__).resolve().parent          # …/driver_create/agent
_ROOT_DIR = _PKG_DIR.parent                           # …/driver_create

for _p in (str(_PKG_DIR), str(_ROOT_DIR)):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)
