"""
driver_create/config.py — 配置入口

集中管理目录、凭证、模型与调优参数。
外部目录默认值适配当前部署环境，可用同名环境变量覆盖。
"""
import os
from pathlib import Path

# ─── 目录结构 ──────────────────────────────────────────────────────
DRIVER_CREATE_DIR = Path(__file__).parent.resolve()

# 产物统一收进 artifacts/（output / intermediate / logs / coverage）
ARTIFACTS_DIR = DRIVER_CREATE_DIR / "artifacts"
OUTPUT_DIR = ARTIFACTS_DIR / "output"
INTERMEDIATE_DIR = ARTIFACTS_DIR / "intermediate"
# pipeline 运行日志目录（run_pipeline 的 Tee 落点）；
# 注意与 agent_main.LOGS_DIR（oss-fuzz 构建日志）区分，别混。
PIPELINE_LOGS_DIR = ARTIFACTS_DIR / "logs"

# 源码临时目录（上游项目克隆；原名 src/，重组后改为 source_code/）
SRC_DIR = DRIVER_CREATE_DIR / "source_code"

# 外部目录（可用环境变量覆盖以适配不同部署环境）
OSS_FUZZ_DIR = Path(os.getenv("OSS_FUZZ_DIR", "/root/gyx/oss-fuzz"))
SH_DIR = Path(os.getenv("SH_DIR", "/root/gyx/sh"))
PROJECTS_DIR = Path(os.getenv("PROJECTS_DIR", "/root/gyx/projects"))  # 已有 fuzz driver 语料库

# include 扫描时跳过的 vendor / 平台 / 无关目录
# （避免把第三方或平台专用头当成项目自身头文件）
VENDOR_SKIP_DIRS = {
    '.git', 'build', 'CMakeFiles', '_deps', 'node_modules',
    'third_party', 'third-party', 'thirdparty', 'external',
    'vendor', 'deps', 'subprojects',
    'win32', 'windows', 'msvc', 'darwin', 'ios', 'android',
    'examples', 'example', 'bench', 'benchmark', 'benchmarks',
}

# ─── Neo4j ─────────────────────────────────────────────────────────
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
# 密码不在源码中硬编码，必须由环境变量提供（使用处会校验非空）
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

# ─── LLM 配置 ──────────────────────────────────────────────────────
# Step2 通过 OpenAI 兼容接口（DeepSeek 等）生成 driver。
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "deepseek").lower()
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")
DEEPSEEK_FAST_MODEL = os.getenv("DEEPSEEK_FAST_MODEL", "deepseek-v4-flash")

# ─── agent_repair 调优参数 ─────────────────────────────────────────
DC_MAX_COMPILE_STEPS_PER_DRIVER = int(os.getenv("DC_MAX_COMPILE_STEPS_PER_DRIVER", "3"))
DC_MAX_TEMPLATE_EDITS = int(os.getenv("DC_MAX_TEMPLATE_EDITS", "2"))
# P2 #10：全局 Docker 构建次数上限，防止 N driver × 3 步 × 3 轮 = 90 次空转
DC_GLOBAL_BUILD_BUDGET = int(os.getenv("DC_GLOBAL_BUILD_BUDGET", "30"))


def intermediate_for(project):
    """返回以项目为单位的中间产物目录，自动创建"""
    d = INTERMEDIATE_DIR / project
    d.mkdir(parents=True, exist_ok=True)
    return d


# ─── 三模式骨架驱动重构新增（focus/peer/cross）─────────────────────
# mode 取值: "focus" | "peer" | "cross" | None
# mode=None 时 output_for 退回原路径 artifacts/output/<project>/，旧数据可读。

MODES = ("focus", "peer", "cross")

# 骨架驱动重构：角色词表版本 + 排序字段（§2.1/§2.2）
# contracts.plans / contracts.skeletons / skeleton_mine / plan_gen 共用，单点定义
PLAN_VERSION = "v4"           # vocab_version：create/configure/data_sink/process/destroy
ORDER_FIELD = "order_last"    # CALLS 边排序字段（按末次出现，§2.2 已验证）
ROLES = ("create", "configure", "data_sink", "process", "destroy")
# query/unknown 不进骨架序列（§2.1），但可作 confidence 标签出现
ROLE_LABELS_EXTENDED = ROLES + ("query", "unknown")


def shared_dir() -> Path:
    """跨项目共享中间产物目录 artifacts/intermediate/_shared/，自动创建。

    存放: skeletons.json (全局骨架池) / role_apis.jsonl / role_dataset.jsonl
    / phase0_report.txt / scenario/<场景>.json
    """
    d = INTERMEDIATE_DIR / "_shared"
    d.mkdir(parents=True, exist_ok=True)
    return d


def scenario_dir() -> Path:
    """场景级产物目录 artifacts/intermediate/_shared/scenario/，自动创建。

    每个场景一份 <scenario>.json（usable_drivers/confidence/peer_projects_ranked...）
    """
    d = shared_dir() / "scenario"
    d.mkdir(parents=True, exist_ok=True)
    return d


def output_for(project, mode=None) -> Path:
    """driver 源码产物目录的路径解析（不创建目录）。

    mode=None  → artifacts/output/<project>/driver/        （旧路径兼容）
    mode="x"   → artifacts/output/<project>/driver/<mode>/ （三模式隔离）

    纯路径函数，无副作用；写者（step2）需自行 mkdir，读者（扫描）可安全调用。
    """
    base = OUTPUT_DIR / project / "driver"
    if mode:
        base = base / mode
    return base


def oss_bin_for(project, mode=None) -> Path:
    """编译产物（二进制）目录的路径解析（不创建目录）。

    mode=None  → artifacts/output/<project>/oss-bin/
    mode="x"   → artifacts/output/<project>/oss-bin/<mode>/
    """
    base = OUTPUT_DIR / project / "oss-bin"
    if mode:
        base = base / mode
    return base


def plan_path(project, mode) -> Path:
    """plan_<mode>.json 路径（不自动创建父目录；调用方负责）。

    位于 artifacts/intermediate/<project>/plan_<mode>.json。
    mode 必须非空（plan 是 mode-specific 的）。
    """
    if not mode:
        raise ValueError("plan_path 需要非空 mode 参数（focus/peer/cross）")
    return INTERMEDIATE_DIR / project / f"plan_{mode}.json"
