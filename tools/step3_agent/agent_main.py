"""
driver_create/agent_main.py — 主 Agent（注入）+ 确定性动作（restage / build / diff）

职责：把 step2 生成的 driver 注入 OSS-Fuzz 项目，调用 get_oss_fuzzer.sh 构建，
供编排器（agent_pipeline.py）驱动整个修复循环。

可写范围：oss-fuzz/projects/<project>/（Dockerfile / build.sh / staged 的 driver 源文件）

注入分工：
  【确定性机械改动】
    1. restage_drivers              output/<p>/*.<ext> → projects/<p>/
    2. session_backup_injectables   备份 Dockerfile / build.sh 为 .dcbak（会话开始执行一次）
    3. inject_dockerfile_copy       Dockerfile 末尾按后缀加 COPY 指令
    4. inject_buildsh_nonfatal_head build.sh shebang 后插 set +e（官方构建失败不中断）
    5. write_buildsh_driver_loop    build.sh 末尾写「保存官方 RC + agent 生成的编译循环 + exit 0」

  【LLM agent 生成编译循环体】
    - agent_main_inject → 上面 1~4 确定性完成后，agent 用工具探查原 harness 的 -I/链接库，
      submit_compile_loop 提交纯 bash 循环体，由 (5) 机械包装写入 build.sh

构建鲁棒性：
    - agent_main_build 遇到 git clone 网络失败自动重试，最多 6 次（仅网络类失败重试）

不改 step1/step2/config；只依赖 agent_common 的确定性底座。
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from config import (OUTPUT_DIR, OSS_FUZZ_DIR, SRC_DIR, DRIVER_CREATE_DIR,
                    DC_GLOBAL_BUILD_BUDGET,
                    intermediate_for, output_for, oss_bin_for, MODES)

# P2 #10：全局 Docker 构建计数器（agent_main_build 递增，agent_pipeline 每轮检查上限）
_GLOBAL_BUILD_COUNT = 0


def global_build_count() -> int:
    """返回当前累计的 Docker 构建次数（agent_main_build 每次递增）。"""
    return _GLOBAL_BUILD_COUNT
from tools.step3_agent import agent_common as ac

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


OSS_FUZZ_PROJECTS = OSS_FUZZ_DIR / "projects"
GET_OSS_FUZZER_SH = DRIVER_CREATE_DIR / "scripts" / "get_oss_fuzzer.sh"
LOGS_DIR = DRIVER_CREATE_DIR / "artifacts" / "logs"     # get_oss_fuzzer.sh 的 OUTPUT_LOG 根

DRIVER_SOURCE_EXTS = (".c", ".cc", ".cpp", ".cxx")

# step2 生成的 driver 文件名 stem 统一以此结尾（foo_crfuzzer.cpp / foo_v2_crfuzzer.cpp）。
# Dockerfile COPY / build.sh 编译循环用它做精确 glob，避免误匹配项目自带的其它 *.c/*.cpp。
DRIVER_STEM_SUFFIX = "_crfuzzer"

# staged_manifest.json：记录本次 stage 到 projects/<project>/ 的文件名，
# 供下次 restage 精准清理（避免误删项目自带 harness）
STAGED_MANIFEST = "staged_manifest.json"

# 注入标记块（幂等重写的锚）
# DC_TAIL_* 与 agent_common.MARKER_* 字面相同，统一引用单一来源（避免两边各定义一份、
# 改一边静默错位 → 修复 agent 找不到块走追加分支，在 exit 0 之后追加第二个块永不执行）。
DC_TAIL_BEGIN = ac.MARKER_BEGIN   # 末尾块：Dockerfile COPY / build.sh 编译循环
DC_TAIL_END = ac.MARKER_END
DC_HEAD_BEGIN = "# >>> dc-injected-head >>>"   # build.sh 头部块：set +e（另一对，用途不同，保留独立定义）
DC_HEAD_END = "# <<< dc-injected-head <<<"

# 主 agent 可备份/注入的文件
INJECTABLE_FILES = {"Dockerfile", "build.sh"}

# DC_ONLY 单编加速守卫（注入到 build.sh 尾块，编译循环之前）。
# 若容器内 $DC_ONLY 非空：把 $SRC 下 stem != $DC_ONLY 的 *_crfuzzer.* 源移到暂存目录，
# 使随后 agent 生成的 `for src in $SRC/*_crfuzzer.*` 循环只剩目标一个（零侵入 loop_body）。
# $DC_ONLY 为空 → 什么都不做，编全部（向后兼容）。只移动我们 stage 的 driver，不碰官方源。
_DC_ONLY_GUARD = r'''if [ -n "${DC_ONLY:-}" ]; then
  echo "[dc] DC_ONLY=$DC_ONLY -> 单编加速：临时移出其余 driver" >&2
  mkdir -p /tmp/dc_hidden
  for _f in $SRC/*_crfuzzer.*; do
    [ -e "$_f" ] || continue
    _b=$(basename "$_f"); _stem=${_b%.*}
    if [ "$_stem" != "$DC_ONLY" ]; then mv "$_f" /tmp/dc_hidden/ 2>/dev/null || true; fi
  done
fi'''

# 容器常只有运行时 .so.1 缺开发包 .so；agent 注入的 clang -lxxx 需要 .so，创建符号链接兜底
_SO_SYMLINK_GUARD = r'''# [dc] 创建 .so -> .so.1 符号链接（容器缺 dev 包时编译循环 -lxxx 兜底）
for _lib in lz4 zstd z lzma bz2 snappy; do
  for _d in /usr/lib/x86_64-linux-gnu /usr/lib /lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu; do
    [ -f "$_d/lib$_lib.so.1" ] && [ ! -e "$_d/lib$_lib.so" ] && ln -sf "lib$_lib.so.1" "$_d/lib$_lib.so" 2>/dev/null || true
  done
done'''

# git clone / 网络类失败特征（命中则 agent_main_build 重试）。全部小写匹配。
_GIT_CLONE_FAIL_PATTERNS = (
    "fatal: unable to access",
    "could not resolve host",
    "temporary failure in name resolution",
    "fatal: could not read from remote repository",
    "fatal: clone of",
    "fetch-pack: unexpected disconnect",
    "error: rpc failed",
    "rpc failed",
    "early eof",
    "the remote end hung up unexpectedly",
    "gnutls_handshake() failed",
    "the tls connection was non-properly terminated",
    "ssl_error",
    "failed to connect to",
    "connection timed out",
    "connection reset by peer",
    "network is unreachable",
    "operation timed out",
    "curl: (6",     # couldn't resolve host
    "curl: (7",     # failed to connect
    "curl: (28",    # timeout
    "curl: (35",    # ssl connect error
    "curl: (52",    # empty reply
    "curl: (56",    # recv failure
)


# ══════════════════════════════════════════════════════════════════════
# 源码确保：从 project.yaml 自动克隆（确定性）
# ══════════════════════════════════════════════════════════════════════

def ensure_source_code(project: str) -> bool:
    """确保 source_code/<project> 存在，不存在则从 project.yaml 的 main_repo 克隆。

    返回 True 表示源码就绪（已存在或成功克隆），False 表示失败。
    """
    source_path = SRC_DIR / project

    # 1. 检查是否已存在且非空
    if source_path.exists() and source_path.is_dir():
        try:
            if any(source_path.iterdir()):
                print(f"  [ensure_source] source_code/{project} 已存在")
                return True
        except OSError:
            pass

    # 2. 读取 project.yaml 获取 main_repo
    project_yaml_path = OSS_FUZZ_PROJECTS / project / "project.yaml"
    if not project_yaml_path.exists():
        print(f"  [ensure_source] ⚠️ 找不到 {project_yaml_path}，无法自动克隆")
        return False

    if not YAML_AVAILABLE:
        print("  [ensure_source] ⚠️ 缺少 PyYAML，无法解析 project.yaml。请 pip install pyyaml")
        return False

    try:
        with open(project_yaml_path, 'r', encoding='utf-8') as f:
            project_config = yaml.safe_load(f)
    except Exception as e:
        print(f"  [ensure_source] ⚠️ 解析 project.yaml 失败: {e}")
        return False

    main_repo = project_config.get('main_repo')
    if not main_repo:
        print(f"  [ensure_source] ⚠️ project.yaml 中没有 main_repo 字段")
        return False

    # 3. git clone
    print(f"  [ensure_source] 从 {main_repo} 克隆到 source_code/{project} ...")
    SRC_DIR.mkdir(parents=True, exist_ok=True)

    try:
        cmd = ["git", "clone", "--depth=1", main_repo, str(source_path)]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600, env=os.environ.copy()
        )
        if result.returncode == 0:
            print(f"  [ensure_source] ✅ 克隆成功")
            return True
        else:
            print(f"  [ensure_source] ❌ 克隆失败 (rc={result.returncode})")
            print(f"    stderr: {result.stderr[:300]}")
            return False
    except subprocess.TimeoutExpired:
        print(f"  [ensure_source] ❌ 克隆超时（600s）")
        return False
    except Exception as e:
        print(f"  [ensure_source] ❌ 克隆异常: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════
# 收集 driver 源 + 期望/实际产物比对（确定性）
# ══════════════════════════════════════════════════════════════════════

def _is_intermediate(name: str) -> bool:
    """跳过修复过程的临时/中间产物（与 step3.collect_drivers 一致）。"""
    return "_fix_r" in name or "_compile_errors" in name


def _driver_stem_suffix(mode: Optional[str] = None) -> str:
    """driver stem 后缀（用于 glob 与 manifest 命名隔离）。

    mode=None  → '_crfuzzer'             （legacy，兼容历史扁平布局）
    mode='x'   → '_x_crfuzzer'           （三模式：focus/peer/cross）

    文件名带 mode 是子目录隔离之外的「安全网」：即便文件脱离 <mode>/ 子目录，
    靠 stem 也能区分所属模式，避免 restage/编译循环里串台。
    """
    if mode:
        return f"_{mode}{DRIVER_STEM_SUFFIX}"
    return DRIVER_STEM_SUFFIX


def collect_driver_sources(project: str, mode: Optional[str] = None) -> list[Path]:
    """扫描 output/<project>/[<mode>/] 下的 driver 源文件（按 stem 去重，跳过中间产物）。

    mode=None  → output/<project>/ 扁平布局，glob *_crfuzzer.{ext}（legacy）
    mode='x'   → output/<project>/x/ 子目录，glob *_x_crfuzzer.{ext}
    """
    base = output_for(project, mode)
    if not base.is_dir():
        return []
    suffix = _driver_stem_suffix(mode)
    sources: list[Path] = []
    seen: set[str] = set()
    for ext in DRIVER_SOURCE_EXTS:
        for f in sorted(base.glob(f"*{suffix}{ext}")):
            if _is_intermediate(f.name) or f.stem in seen:
                continue
            seen.add(f.stem)
            sources.append(f)
    return sources


def expected_binaries(project: str, mode: Optional[str] = None) -> set[str]:
    """期望产物名 = 每个 driver 源文件的 stem（foo_focus_crfuzzer.c → foo_focus_crfuzzer）。"""
    return {f.stem for f in collect_driver_sources(project, mode)}


def actual_binaries(project: str, mode: Optional[str] = None) -> set[str]:
    """实际产物 = oss-bin/[<mode>/] 下的可执行文件。

    mode=None  → artifacts/output/<project>/oss-bin/ 扁平（legacy）
    mode='x'   → artifacts/output/<project>/oss-bin/<mode>/ 子目录

    产物比对一律以此目录为准，不读 build/out/<project>/。
    """
    bin_dir = oss_bin_for(project, mode)
    if not bin_dir.is_dir():
        return set()

    if mode:
        return {f.name for f in bin_dir.iterdir()
                if f.is_file() and os.access(f, os.X_OK)}

    # legacy 扁平
    return {f.name for f in bin_dir.iterdir()
            if f.is_file() and os.access(f, os.X_OK)}


def diff_products(project: str, mode: Optional[str] = None) -> tuple[set[str], set[str]]:
    """返回 (built, failed)：built = 期望∩实际，failed = 期望 - 实际。分诊只针对 failed。"""
    expected = expected_binaries(project, mode)
    actual = actual_binaries(project, mode)
    built = expected & actual
    failed = expected - actual
    return built, failed


def driver_extensions(project: str, mode: Optional[str] = None) -> set[str]:
    """本项目（该 mode 下）driver 用到的后缀集合（如 {'.c'} 或 {'.cc', '.cpp'}）。
    供注入时决定 Dockerfile 的 `COPY *<ext> $SRC/` glob。"""
    return {f.suffix for f in collect_driver_sources(project, mode)}


def driver_copy_globs(project: str, mode: Optional[str] = None) -> list[str]:
    """生成 Dockerfile COPY 用的精确 glob 列表（每个后缀一条）。

    driver stem 统一以 `_[:mode:]_crfuzzer` 结尾（mode=None 时为 `_crfuzzer`，
    含 `_v{n}_crfuzzer` 变体），故优先收紧成 `*<suffix><ext>`，避免把项目自带的
    其它 `*.c/*.cpp` 误 COPY 进 `$SRC/`。但为稳妥：某后缀下只要有一个 driver **不**
    以该 suffix 结尾，该后缀就回落到宽 glob `*<ext>`（宁可多拷、绝不漏拷）。
    """
    suffix = _driver_stem_suffix(mode)
    by_ext: dict[str, list[Path]] = {}
    for f in collect_driver_sources(project, mode):
        by_ext.setdefault(f.suffix, []).append(f)
    globs: list[str] = []
    for ext in sorted(by_ext):
        files = by_ext[ext]
        if all(f.stem.endswith(suffix) for f in files):
            globs.append(f"*{suffix}{ext}")   # 精确：COPY *_focus_crfuzzer.cpp $SRC/
        else:
            globs.append(f"*{ext}")            # 回落：COPY *.cpp $SRC/
    return globs


# ══════════════════════════════════════════════════════════════════════
# restage_drivers：manifest-guarded，首轮 touch-none（确定性）
# ══════════════════════════════════════════════════════════════════════

def _manifest_path(project: str, mode: Optional[str] = None) -> Path:
    """staged manifest 路径。mode=None → staged_manifest.json（legacy）；mode='x' → staged_manifest_x.json"""
    name = STAGED_MANIFEST if not mode else f"staged_manifest_{mode}.json"
    return intermediate_for(project) / name


def _load_staged_manifest(project: str, mode: Optional[str] = None) -> list[str]:
    mp = _manifest_path(project, mode)
    if not mp.exists():
        return []
    try:
        data = json.loads(mp.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, dict):
        return list(data.get("staged", []))
    if isinstance(data, list):
        return list(data)
    return []


def _write_staged_manifest(project: str, staged: list[str],
                           mode: Optional[str] = None) -> None:
    mp = _manifest_path(project, mode)
    mp.write_text(
        json.dumps({"project": project, "mode": mode, "staged": sorted(staged)},
                   indent=2, ensure_ascii=False)
    )


def restage_drivers(project: str, mode: Optional[str] = None) -> list[str]:
    """把 output/<project>/[<mode>/] 的当前 driver 复制到 projects/<project>/（Docker 构建上下文，扁平）。

    mode 通过文件名（_<mode>_crfuzzer）隔离，不建子目录——projects/<p>/ 是共享构建上下文，
    各 mode 文件名不冲突。restage 只动本 mode manifest 记录过的文件（manifest 也 mode 隔离）。

    清理策略：
      - 只删【本 mode manifest】记录过、且这次不再产出的文件；
      - 首轮无 manifest → 不删任何东西（避免误删项目自带 harness 或他 mode 文件）；
      - 复制后写回新 manifest。
    """
    dest_dir = OSS_FUZZ_PROJECTS / project
    if not dest_dir.is_dir():
        raise RuntimeError(f"[agent_main] OSS-Fuzz 项目目录不存在: {dest_dir}")

    sources = collect_driver_sources(project, mode)
    new_names = {f.name for f in sources}

    # 1. 清理上一次 stage 的、且这次不再产出的文件（只动本 mode manifest 记录过的）
    prev_staged = set(_load_staged_manifest(project, mode))
    for name in prev_staged - new_names:
        stale = dest_dir / name
        if stale.exists():
            try:
                stale.unlink()
            except OSError as e:
                print(f"  [restage] 警告：删除旧 stage 文件失败 {name}: {e}")

    # 2. 复制当前 driver 过去
    staged: list[str] = []
    for src in sources:
        try:
            shutil.copy2(src, dest_dir / src.name)
            staged.append(src.name)
        except OSError as e:
            print(f"  [restage] 警告：复制 {src.name} 失败: {e}")

    # 3. 写回 manifest
    _write_staged_manifest(project, staged, mode)
    tag = f"[{mode}]" if mode else "[legacy]"
    print(f"  [restage] {tag} {project}: stage {len(staged)} 个 driver 到 {dest_dir}")
    return staged


# ══════════════════════════════════════════════════════════════════════
# 备份 + 标记块工具（确定性）
# ══════════════════════════════════════════════════════════════════════

def session_backup_injectables(project: str) -> None:
    """会话开始：把 Dockerfile / build.sh 备份成 .dcbak（在任何修改之前，只调一次）。

    overwrite=False：仅当 .dcbak 不存在时才创建，保留会话前原始快照。
    避免 P2 #12：第二次运行时 overwrite=True 会用含注入块的当前 build.sh 覆盖原始 .dcbak，
    原始永久丢失。"""
    proj_dir = OSS_FUZZ_PROJECTS / project
    for name in sorted(INJECTABLE_FILES):
        f = proj_dir / name
        if f.exists():
            created = ac.backup_build_file(f, overwrite=False)
            if created:
                print(f"  [backup] {name} → {name}.dcbak")
            # .dcbak 已存在则不覆盖，保留原始快照


def _guarded_block_write(project: str, fname: str, body: str) -> str:
    """把 body 写入 oss-fuzz/projects/<project>/<fname> 的 dc-injected 标记块（幂等）。

    供 agent_build_fix 的 write_marked_block 工具调用。guarded = 四层保护：
      1. fname 白名单（仅 INJECTABLE_FILES）
      2. build.sh 编译块完整性校验（保留 DC_OFFICIAL_RC 与 exit 0）
      3. 写前 backup_build_file(overwrite=False) 保留会话前 .dcbak 快照
      4. 只替换标记块内、块外原文不动（replace_or_append_marked_block 幂等语义）
    """
    if fname not in INJECTABLE_FILES:
        return f"[error] 只能写 {sorted(INJECTABLE_FILES)}，收到 {fname!r}"
    path = OSS_FUZZ_PROJECTS / project / fname
    if not path.is_file():
        return f"[error] {path} 不存在"
    if fname == "build.sh" and ("exit 0" not in body or "DC_OFFICIAL_RC" not in body):
        return ("[error] 写入被拒绝：编译块必须保留 DC_OFFICIAL_RC=$? 和结尾的 exit 0。"
                "请先 read_marked_block 读取当前完整块，在其基础上修改后整体写回。")
    try:
        ok = ac.replace_or_append_marked_block(path, body)
    except Exception as e:
        return f"[error] 写入失败: {e}"
    return (f"ok (dc-injected block updated in {fname})" if ok
            else f"[error] 写入未生效: {fname}")


def _strip_marked_block(text: str, begin: str, end: str) -> str:
    """删除 begin..end（含标记行）之间的内容，实现幂等重写。"""
    out, skip = [], False
    for ln in text.splitlines(keepends=True):
        s = ln.strip()
        if s == begin:
            skip = True
            continue
        if s == end:
            skip = False
            continue
        if not skip:
            out.append(ln)
    return "".join(out)


# ══════════════════════════════════════════════════════════════════════
# 确定性注入：Dockerfile COPY / build.sh set+e 头 / build.sh 编译循环尾
# ══════════════════════════════════════════════════════════════════════

def inject_dockerfile_copy(project: str, mode: Optional[str] = None) -> str:
    """在 Dockerfile 末尾用 dc-injected 标记块加 `COPY *<suffix><ext> $SRC/`，把 driver 源拷进 $SRC/。

    mode=None → glob `*_crfuzzer<ext>`（legacy）
    mode='x'  → glob `*_x_crfuzzer<ext>`（只拷该 mode 的 driver，与他 mode 隔离）

    按实际 driver 后缀 + stem 后缀生成精确 glob（.c/.cc/.cpp/.cxx 均可）；某后缀下若有
    不以该 suffix 命名的 driver 则该后缀回落到宽 glob（见 driver_copy_globs）。
    幂等（先剥离旧块再追加）。假定备份已由 session_backup_injectables 完成。
    """
    path = OSS_FUZZ_PROJECTS / project / "Dockerfile"
    if not path.is_file():
        return f"[error] 未找到 {path}"
    globs = driver_copy_globs(project, mode)
    if not globs:
        return "[warn] 无 driver 源，跳过 Dockerfile COPY"
    copy_lines = "\n".join(f"COPY {g} $SRC/" for g in globs)   # 如 COPY *_focus_crfuzzer.cpp $SRC/
    text = _strip_marked_block(path.read_text(errors="ignore"), DC_TAIL_BEGIN, DC_TAIL_END)
    block = f"{DC_TAIL_BEGIN}\n{copy_lines}\n{DC_TAIL_END}\n"
    path.write_text(text.rstrip() + "\n\n" + block)
    return f"ok (COPY {', '.join(globs)} -> $SRC/)"


def inject_buildsh_nonfatal_head(project: str) -> str:
    """在 build.sh 的 shebang 之后插入 dc-injected-head 块（`set +e`），使官方构建失败
    不因 errexit 中断脚本。幂等。假定备份已完成。

    退出码的保存放在末尾编译块（write_buildsh_driver_loop）里 `DC_OFFICIAL_RC=$?`，
    这样能抓到官方构建体最后一条命令的退出码；末尾块最终 `exit 0` 让 build.sh 整体成功，
    保证 get_oss_fuzzer.sh 的 set -e 不会在提取产物前中止。
    """
    path = OSS_FUZZ_PROJECTS / project / "build.sh"
    if not path.is_file():
        return f"[error] 未找到 {path}"
    text = _strip_marked_block(path.read_text(errors="ignore"), DC_HEAD_BEGIN, DC_HEAD_END)
    lines = text.splitlines(keepends=True)
    insert_at = 1 if (lines and lines[0].startswith("#!")) else 0
    head = (f"{DC_HEAD_BEGIN}\n"
            f"set +e   # dc: 允许官方构建失败，不因 errexit 中断；退出码在末尾块保存\n"
            f"{DC_HEAD_END}\n")
    lines.insert(insert_at, head)
    path.write_text("".join(lines))
    return "ok (set +e injected after shebang)"


def write_buildsh_driver_loop(project: str, loop_body: str) -> str:
    """在 build.sh 末尾写 dc-injected 块：保存官方构建退出码 + agent 生成的 driver 编译循环 + exit 0。

    `exit 0` 关键：保证 build.sh 成功 → build_fuzzers 成功 → get_oss_fuzzer.sh 不因 set -e 跳过提取。
    幂等（先剥离旧尾块再追加）。假定备份已完成。

    DC_ONLY 单编加速（通用，零侵入 loop_body）：编译前若环境变量 `$DC_ONLY` 非空，把 `$SRC` 下
    stem != $DC_ONLY 的 driver 源文件临时移出，使 agent 生成的 `for src in $SRC/*_crfuzzer.*`
    循环天然只编目标那一个；$DC_ONLY 为空则编全部（向后兼容，行为不变）。移动只碰我们 stage 的
    `*_crfuzzer.*`，不触官方源文件。
    """
    path = OSS_FUZZ_PROJECTS / project / "build.sh"
    if not path.is_file():
        return f"[error] 未找到 {path}"
    text = _strip_marked_block(path.read_text(errors="ignore"), DC_TAIL_BEGIN, DC_TAIL_END)
    block = (
        f"{DC_TAIL_BEGIN}\n"
        f"DC_OFFICIAL_RC=$?\n"
        f'echo "[dc] official build exit code: $DC_OFFICIAL_RC" >&2\n'
        f"{_DC_ONLY_GUARD}\n"
        f"{_SO_SYMLINK_GUARD}\n"
        f"{loop_body.rstrip()}\n"
        f"exit 0\n"
        f"{DC_TAIL_END}\n"
    )
    path.write_text(text.rstrip() + "\n\n" + block)
    return "ok (driver compile loop written to build.sh tail)"


# ══════════════════════════════════════════════════════════════════════
# build：跑 get_oss_fuzzer.sh，返回 log 路径（确定性 + 网络失败重试）
# ══════════════════════════════════════════════════════════════════════

def build_log_path(project: str) -> Path:
    """get_oss_fuzzer.sh 的 OUTPUT_LOG 路径（每次运行覆盖）。"""
    return LOGS_DIR / f"{project}.log"


def _read_log_tail(log_path: Path, n: int = 30) -> str:
    if not log_path.is_file():
        return ""
    try:
        return "\n".join(log_path.read_text(errors="ignore").splitlines()[-n:])
    except OSError:
        return ""


def read_dc_official_rc(log_path: Path) -> int:
    """从构建 log 读 DC_OFFICIAL_RC（官方构建退出码）。

    get_oss_fuzzer.sh 的 build.sh 尾块 echo "[dc] official build exit code: $DC_OFFICIAL_RC"。
    返回退出码（0=成功，非 0=官方构建失败）；读不到返回 0（兼容旧 log）。
    """
    if not log_path.is_file():
        return 0
    import re
    try:
        text = log_path.read_text(errors="ignore")
        m = re.search(r"official build exit code:\s*(-?\d+)", text)
        return int(m.group(1)) if m else 0
    except (OSError, ValueError):
        return 0


def _looks_like_network_failure(text: str) -> bool:
    """判断构建输出/日志是否命中 git clone 网络类失败特征。

    省 context：git clone 的网络失败一定发生在 `git clone` / `Cloning into` 附近，
    先把含这些标志的行及其上下文（各 ±8 行）抠出来，只在这些片段里找网络特征；
    只有在完全找不到 clone 标志时，才退回全文匹配（兜底，避免漏判）。
    """
    lines = text.splitlines()
    clone_idxs = [i for i, ln in enumerate(lines)
                  if "git clone" in ln.lower() or "cloning into" in ln.lower()]
    if clone_idxs:
        window: list[str] = []
        for i in clone_idxs:
            lo, hi = max(0, i - 8), min(len(lines), i + 9)
            window.extend(lines[lo:hi])
        scope = "\n".join(window).lower()
        return any(p in scope for p in _GIT_CLONE_FAIL_PATTERNS)
    # 没有 clone 标志：兜底全文匹配（clone 失败也可能没打印 "git clone" 字样）
    low = text.lower()
    return any(p in low for p in _GIT_CLONE_FAIL_PATTERNS)


def _backup_and_clean_oss_bin(project: str, mode: Optional[str] = None,
                              dc_only: Optional[str] = None) -> None:
    """P0-1 双保险：调 get_oss_fuzzer.sh 前在 Python 侧也备份+清理陈旧产物。

    dc_only 非空（DC_ONLY 单编修复模式）：只删目标二进制，不清整个 oss-bin/<mode>/，
    保留其他已修好的二进制（否则逐个修复时前一个会被删，最后只剩最后一个）。
    dc_only 为空（全量编）：备份整个 oss-bin/<mode>/ + 清空，防 diff 假阳性。
    """
    import time
    ts = time.strftime("%Y%m%d_%H%M%S")
    extract_dir = oss_bin_for(project, mode)
    # 确保父目录 oss-bin/ 存在（新项目首次跑 step3 时不存在）
    extract_dir.parent.mkdir(parents=True, exist_ok=True)

    # DC_ONLY 单编模式：只删目标二进制，保留其他
    if dc_only:
        target_bin = extract_dir / dc_only
        if target_bin.is_file():
            target_bin.unlink()
        # 仍清顶层扁平残留 + 旧 .bak
        for flat in extract_dir.parent.iterdir():
            if flat.is_file() and "_crfuzzer" in flat.name:
                flat.unlink()
        for old_bak in extract_dir.parent.glob(f"{extract_dir.name}.bak.*"):
            shutil.rmtree(old_bak, ignore_errors=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
        return

    # 全量编模式：备份整个 oss-bin/<mode>/ + 清空
    # 0. 先清理同目录下所有旧 .bak.*（防堆积，只留最近一次语义）
    for old_bak in extract_dir.parent.glob(f"{extract_dir.name}.bak.*"):
        shutil.rmtree(old_bak, ignore_errors=True)
    # 0b. 清理顶层 oss-bin/ 下残留的扁平二进制（历史扁平提取的，非 mode 子目录）
    for flat in extract_dir.parent.iterdir():
        if flat.is_file() and "_crfuzzer" in flat.name:
            flat.unlink()
    # 1. oss-bin/[<mode>/] 备份（非空才动，只留最近一次）
    if extract_dir.is_dir() and any(extract_dir.iterdir()):
        bak = extract_dir.parent / f"{extract_dir.name}.bak.{ts}"
        try:
            shutil.move(str(extract_dir), str(bak))
            print(f"  [build] [dc] 备份旧 oss-bin: {extract_dir.name} → {bak.name}")
        except OSError as e:
            print(f"  [build] [dc] ⚠️ 备份失败（继续清理）: {e}")
            shutil.rmtree(extract_dir, ignore_errors=True)
    # 2. build/out/<p> 直接删（中间产物，每次重建）
    out_dir = OSS_FUZZ_DIR / "build" / "out" / project
    if out_dir.is_dir():
        shutil.rmtree(out_dir, ignore_errors=True)
        print(f"  [build] [dc] 清理 build/out/{project}（中间产物）")
    # 3. 新建空 oss-bin/[<mode>/] 承接本轮产物
    extract_dir.mkdir(parents=True, exist_ok=True)


def agent_main_build(project: str, timeout: int = 1800,
                     max_retries: int = 5, retry_wait: int = 10,
                     dc_only: Optional[str] = None,
                     mode: Optional[str] = None) -> Path:
    """跑 scripts/get_oss_fuzzer.sh <project> [dc_only] [mode]（build_image → build_fuzzers → 提取到 oss-bin/[<mode>/]）。
    返回 log 路径 artifacts/logs/<project>.log。

    dc_only：非空时开启 DC_ONLY 单编加速——把目标 stem 作为第 2 个参数传给 get_oss_fuzzer.sh，
    容器内 build.sh 尾块的 DC_ONLY 守卫据此只编该 driver（见 _DC_ONLY_GUARD）。为空则全量编译。

    mode：非空时作为第 3 个参数传给脚本，控制 oss-bin 提取子目录（focus/peer/cross）。

    网络失败重试：
      build_image 阶段的 git clone 若因网络问题失败（DNS/连接超时/RPC failed/TLS 中断等），
      直接重跑整个脚本，最多重试 max_retries 次（默认 5）。仅对「网络类失败」重试；
      普通编译失败不重试（交给分诊）；超时不当网络重试（避免全量构建空转）。

      注意：git clone 输出被脚本用 `>>` 重定向进 logs/<project>.log（不进 subprocess stdout），
      故网络失败判定必须读该 log 文件 —— 下面把 subprocess 输出与 log 文件合并成 haystack 判定。

    必须在 OSS_FUZZ_DIR 下执行（脚本内部 cd 到该目录；此处显式设 cwd 双保险，
    并遵守 CLAUDE.md「OSS-Fuzz 构建必须在 /root/gyx/oss-fuzz 路径下执行」）。
    """
    log_path = build_log_path(project)
    if not GET_OSS_FUZZER_SH.is_file():
        raise RuntimeError(f"[agent_main] 找不到构建脚本: {GET_OSS_FUZZER_SH}")

    # P0-1 双保险：Python 侧先备份+清理陈旧产物（脚本侧也有同逻辑，无副作用）
    _backup_and_clean_oss_bin(project, mode, dc_only=dc_only)

    cmd = ["bash", str(GET_OSS_FUZZER_SH), project]
    if dc_only:
        cmd.append(dc_only)  # get_oss_fuzzer.sh <project> <dc_only_target>
    elif mode:
        cmd.append("")  # 空占位，让 mode 传到 $3（否则 mode 被当 dc_only）
    if mode:
        cmd.append(mode)     # get_oss_fuzzer.sh <project> <dc_only> <mode>

    # P2 #10：全局构建次数递增（agent_pipeline 据此跳过空转）
    global _GLOBAL_BUILD_COUNT
    _GLOBAL_BUILD_COUNT += 1

    # attempt 1..(max_retries+1)：最多 max_retries 次重试（首跑 + 5 次重试 = 至多 6 次）
    for attempt in range(1, max_retries + 2):
        tag = f"attempt {attempt}/{max_retries + 1}"
        print(f"  [build] $ {' '.join(cmd)}  (cwd={OSS_FUZZ_DIR}, timeout={timeout}s, {tag})")
        try:
            result = subprocess.run(
                cmd, cwd=str(OSS_FUZZ_DIR),
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            # 超时不当网络重试（可能是构建本身慢）；记录后返回
            print(f"  [build] 超时（{timeout}s），log 见 {log_path}")
            try:
                LOGS_DIR.mkdir(parents=True, exist_ok=True)
                with open(log_path, "a") as fh:
                    fh.write(f"\n[agent_main] BUILD TIMEOUT after {timeout}s ({tag})\n")
            except OSError:
                pass
            return log_path
        except OSError as e:
            print(f"  [build] 启动失败: {e}")
            return log_path

        if result.returncode == 0:
            if attempt > 1:
                print(f"  [build] 重试成功（{tag}）")
            return log_path

        # 非零退出：合并 subprocess 输出 + log 文件判定是否网络类失败
        combined = (result.stdout or "") + "\n" + (result.stderr or "")
        haystack = combined + "\n" + (log_path.read_text(errors="ignore")
                                      if log_path.is_file() else "")
        if _looks_like_network_failure(haystack) and attempt <= max_retries:
            print(f"  [build] 检测到 git clone / 网络失败（{tag}），{retry_wait}s 后重跑脚本...")
            time.sleep(retry_wait)
            continue

        # 非网络失败，或已到重试上限 → 返回，交给上层/分诊
        if _looks_like_network_failure(haystack):
            print(f"  [build] 网络失败重试已达上限（{max_retries} 次），放弃。log: {log_path}")
        else:
            print(f"  [build] 构建返回 {result.returncode}（{tag}，非网络类失败，不重试）。log: {log_path}")
        return log_path

    return log_path


# ══════════════════════════════════════════════════════════════════════
# replay_via_get_oss_fuzzer：供 agent_repair 的 replay_fn（确定性）
# ══════════════════════════════════════════════════════════════════════

def replay_via_get_oss_fuzzer(project: str, base: str, binary_name: str,
                              mode: Optional[str] = None) -> tuple[bool, str]:
    """单 driver 重编入口，签名/返回契约与 step3.try_replay_driver_build 一致
    （replay_fn(project, base, binary_name) -> (ok, reason)；失败 reason 以 "replay rc!=0" 开头）。

    agent_repair 已把修好的源码写回 output/<project>/[<mode>/]<file>，这里 restage 该 driver →
    跑 get_oss_fuzzer.sh（含网络失败重试）→ 看 oss-bin/<project>/[<mode>/]<binary_name> 是否出现。

    mode 透传给 restage_drivers / actual_binaries 做产物查找（与生成阶段保持同一 mode 隔离）。
    get_oss_fuzzer.sh 本身 mode-agnostic（提取到扁平 oss-bin/<project>/），mode 隔离靠文件名
    （_<mode>_crfuzzer）+ actual_binaries 的名字过滤实现。

    DC_ONLY 单编加速：把 binary_name（即目标 driver stem）作为 dc_only 传下去，容器内 build.sh
    尾块只编这一个 driver，其余临时移出，大幅缩短单次修复验证耗时（原本每次全量编 N 个）。
    可用 DC_DISABLE_SINGLE_BUILD=1 关闭回退到全量（排障用）。
    """
    try:
        restage_drivers(project, mode)
    except RuntimeError as e:
        return False, f"replay rc!=0\n[restage 失败] {e}"

    dc_only = None if os.getenv("DC_DISABLE_SINGLE_BUILD") else binary_name
    log_path = agent_main_build(project, timeout=1800, dc_only=dc_only, mode=mode)

    # mode 子目录查（oss_bin_for 已含 mode 子目录）
    bin_path = oss_bin_for(project, mode) / binary_name
    if bin_path.exists() and os.access(bin_path, os.X_OK):
        return True, "编译成功"

    tail = _read_log_tail(log_path, 30)
    return False, f"replay rc!=0\n{tail}"


# ══════════════════════════════════════════════════════════════════════
# 注入 agent（LLM tool loop）：只产出 driver 编译循环体，不写文件
# ══════════════════════════════════════════════════════════════════════

def _list_generated_drivers(project: str, mode: Optional[str] = None) -> str:
    """列 output/<project>/[<mode>/] 下的 driver 源文件及后缀汇总（供注入 agent 决定 glob）。"""
    sources = collect_driver_sources(project, mode)
    tag = f"[{mode}]" if mode else "[legacy]"
    if not sources:
        return f"[empty] output/{project}/{mode + '/' if mode else ''} 下没有 driver 源文件"
    exts = sorted({f.suffix for f in sources})
    lines = [f"# {tag} {len(sources)} 个 driver，后缀: {', '.join(exts)}"]
    lines += [f.name for f in sources[:60]]
    if len(sources) > 60:
        lines.append(f"[... 共 {len(sources)} 个，省略 {len(sources) - 60}]")
    return "\n".join(lines)


INJECT_TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": (
            "读 oss-fuzz/projects/<project>/ 或 SRC_DIR/<project>/ 内文件片段（沙箱）。"
            "先读 build.sh 理解原项目怎么构建库、怎么编自带 harness。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "start_line": {"type": "integer", "default": 1},
                "max_lines": {"type": "integer", "default": 200},
            },
            "required": ["path"],
        },
    },
    {
        "name": "list_dir",
        "description": "列 oss-fuzz/projects/<project>/ 或 SRC_DIR/<project>/ 内某目录一层（沙箱）。",
        "input_schema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "grep",
        "description": (
            "在 oss-fuzz/projects/<project>/ + SRC_DIR/<project>/ 里正则搜索。"
            "用途：找原 build.sh 里编自带 harness 的 `$CC/$CXX ... $LIB_FUZZING_ENGINE` 行，"
            "照抄其 -I include 路径和链接库（.a / -lxxx）。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "globs": {"type": "array", "items": {"type": "string"}},
                "max_results": {"type": "integer", "default": 50},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "list_generated_drivers",
        "description": "列 output/<project>/ 下待编译的 driver 源文件及其后缀（用于确定编译循环的 glob）。",
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "submit_compile_loop",
        "description": (
            "提交你写好的 driver 编译循环体（纯 bash）。它会被自动放进 build.sh 末尾：前面已自动"
            "保存官方构建退出码、后面已自动 exit 0；driver 源码已 COPY 到 $SRC/ 顶层。**不要自己写文件**。\n"
            "loop_body 要求：cd 到项目源码目录（$SRC/<project>），遍历顶层 driver（如 `for src in $SRC/*_crfuzzer.cc`），"
            "用与原 harness 相同的 -I 路径和链接库编译，接 $LIB_FUZZING_ENGINE，输出 $OUT/<stem>；"
            "单个 driver 失败用 if/else 跳过、不中断（保证整体不失败）。"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "loop_body": {"type": "string", "description": "纯 bash 编译循环体"},
                "reason": {"type": "string", "description": "一句话说明复用了原 harness 的哪些 -I/链接库"},
            },
            "required": ["loop_body"],
        },
    },
]


INJECT_SYSTEM_PROMPT = """你是 OSS-Fuzz fuzz driver 流水线的**注入 agent（主 agent）**。

背景：流水线用 LLM 生成了一批 fuzz driver（实现 `LLVMFuzzerTestOneInput` 的 C/C++ 测试桩）。
外层已经确定性地完成了三件事，你**不需要也不能**重复做：
  1. driver 源文件已 COPY 到容器 `$SRC/` 顶层（项目源码树在 `$SRC/<project>/` 下，二者不在同一层）；
  2. build.sh 头部已插入 `set +e`（官方构建失败不会中断脚本）；
  3. build.sh 末尾会自动包上「保存官方退出码 … 你的循环体 … exit 0」。

你唯一的任务：**产出一段 bash 编译循环体（loop_body）**，把 `$SRC/` 顶层的 driver 编译成
`$OUT/<stem>` fuzzer 二进制，然后用 `submit_compile_loop` 提交。**你不写任何文件**。

## 怎么做

1. `read_file` 读 build.sh；`grep` 找原项目编自带 harness 的 `$CC/$CXX ... $LIB_FUZZING_ENGINE`
   编译行，弄清它用哪些 `-I` include 路径、链接哪些库（`.a` 静态库路径 / `-lxxx`）。
   **注意**：有些项目的真实编译逻辑藏在容器构建时才 clone 的外部脚本里（如 aspell 的
   `$SRC/aspell-fuzz/ossfuzz.sh`），本地探查不到——这很正常，别死磕。
2. `list_dir` 看项目源码目录结构、`list_generated_drivers` 看 driver 实际后缀，决定循环 glob
   （如 `.cc` → `for src in $SRC/*_crfuzzer.cc`）。
3. `submit_compile_loop(loop_body, reason)` 提交循环体。**这一步无论如何都要做到**（见硬约束）。

## loop_body 规范（示例，C 项目 libxml2）

    cd $SRC/libxml2
    for src in $SRC/*_crfuzzer.c; do
        name=$(basename "$src" .c)
        echo "Building $name ..."
        if $CC $CFLAGS -I include -I . -I fuzz \\
            "$src" fuzz/fuzz.c ./.libs/libxml2.a -lz -llzma \\
            $LIB_FUZZING_ENGINE -o "$OUT/$name"; then
            echo "Successfully built $name"
        else
            echo "WARNING: Failed to build $name, skipping." >&2
        fi
    done

## 硬约束

- 循环 glob 匹配 driver 实际后缀（先 list_generated_drivers 确认）。生成的 driver 文件名 stem
  统一以 `_crfuzzer` 结尾，故 glob 用 `$SRC/*_crfuzzer<ext>`（如 `$SRC/*_crfuzzer.cc`），
  精确匹配、不会扫到项目自带源码；driver 在 `$SRC/` 顶层，项目源码在 `$SRC/<project>/`，别混。
- 链接项优先级：**能查到就照抄**原 build.sh / 上游脚本里已验证过的 `-I` 路径和链接库；
  **查不到（如逻辑藏在容器才 clone 的外部脚本里）就基于目录结构和常识做一个尽可能合理的猜测**
  —— 目标是先把流程打通，编译不过没关系（后续有分诊+修复 agent 兜底），**绝不能因为"查不到就不敢提交"而空耗步数**。
  猜测时可参考：`list_dir` 到的源码/头文件目录加 `-I`，库名一般是 `-l<项目名>`，静态库常在
  `.libs/lib<项目名>.a` 或 `build/` 下；拿不准就同时给几个候选 `-I`、宁多勿漏。
- C 项目用 `$CC`，C++ 项目用 `$CXX`；始终接 `$LIB_FUZZING_ENGINE`，输出 `$OUT/<stem>`。
- 单 driver 失败必须 `if ...; then ... else echo WARNING >&2; fi` 跳过，不中断整体。
- **每个 driver 编译前必须打印标记行 `echo "Building $name ..."`**（$name 即 `*_crfuzzer` 的 stem）。
  这是分诊 agent 按 driver 切分 log 的锚点，不可省略。
- **最重要**：本轮结束前**必须调用一次 `submit_compile_loop`**。哪怕信息不全，也要基于现有目录信息
  提交一个合理的循环体——这是打通流程的硬性要求，不提交等于失败。
- **不写任何文件**，只 `submit_compile_loop`。"""


def _make_inject_handler(project: str, mode: Optional[str] = None):
    roots = ac.project_roots(project)

    def handler(name: str, args: dict, ctx: dict) -> str:
        if name == "read_file":
            return ac.tool_read_file(args.get("path", ""), roots,
                                     int(args.get("start_line", 1)),
                                     int(args.get("max_lines", 200)))
        if name == "list_dir":
            return ac.tool_list_dir(args.get("path", ""), roots)
        if name == "grep":
            return ac.tool_grep(args.get("pattern", ""), roots,
                                args.get("globs"), int(args.get("max_results", 50)))
        if name == "list_generated_drivers":
            return _list_generated_drivers(project, mode)
        if name == "submit_compile_loop":
            ctx["submit"]({"loop_body": args.get("loop_body", ""),
                           "reason": args.get("reason", "")})
            return json.dumps({"accepted": True}, ensure_ascii=False)
        return f"[error] 未知工具 {name}"

    return handler


def _build_profile_hint(project: str) -> str:
    """从 step1 产出的 build_profile.json 抽 include_dirs / sys_libs 作为注入提示。

    这些是 step1 扫描源码 + header→lib 映射得出的候选（含 library/ 等内部头目录、
    -lfreetype 等系统库）。作为 agent 探查原 build.sh 之外的兜底线索，缺失则返回空串。"""
    try:
        bp_path = intermediate_for(project) / "build_profile.json"
        if not bp_path.is_file():
            return ""
        bp = json.loads(bp_path.read_text(encoding="utf-8"))
    except Exception:
        return ""
    inc = bp.get("include_dirs") or []
    libs = (bp.get("sys_libs") or "").strip()
    parts = []
    if inc:
        parts.append("  - 候选 `-I` 路径（step1 扫描，含内部头目录）: "
                     + " ".join(inc[:10]))
    if libs:
        parts.append(f"  - 候选系统链接库（按头文件推断）: {libs}")
    if not parts:
        return ""
    return ("\n- **build_profile 线索**（探不到原编译行时优先参考，别硬猜）:\n"
            + "\n".join(parts))


def _inject_user_message(project: str, mode: Optional[str] = None) -> str:
    ext_hint = ", ".join(sorted(driver_extensions(project, mode))) or "(未知，用 list_generated_drivers 查)"
    profile_hint = _build_profile_hint(project)
    suffix = _driver_stem_suffix(mode)
    glob_hint = f"$SRC/*{suffix}<ext>"   # mode=None → *_crfuzzer<ext>; mode='focus' → *_focus_crfuzzer<ext>
    mode_tag = f" | mode: {mode}" if mode else ""
    return f"""## 注入任务

- **项目**: `{project}`{mode_tag}
- driver 源已 COPY 到容器 `$SRC/` 顶层，后缀: {ext_hint}；项目源码在 `$SRC/{project}/`。
- build.sh 已加 `set +e`、末尾会自动 `exit 0`。你只需产出编译循环体。{profile_hint}

请：先 read_file build.sh、grep 原 harness 的 `$CC/$CXX ... $LIB_FUZZING_ENGINE` 编译行
弄清 -I 和链接库；list_generated_drivers 确认后缀；再 submit_compile_loop 提交一段遍历
`{glob_hint}`、复用原链接项、单编失败跳过、输出 `$OUT/<stem>` 的循环体。不要写文件。

**注意**：{project} 的真实编译逻辑可能藏在容器构建时才 clone 的外部脚本里，本地探查不到。
若几步内确实找不到原编译行，就基于目录结构做一个**尽可能合理的猜测**（-I 加源码/头文件目录，
链接 `-l{project}` 或 `.libs/lib{project}.a` 之类），**务必在结束前 submit_compile_loop 提交**——
先打通流程，编译不过有后续 agent 兜底，不提交才是失败。"""


def agent_main_inject(project: str, max_steps: int = 16,
                      model: Optional[str] = None,
                      mode: Optional[str] = None) -> bool:
    """主 agent 注入入口。顺序严格：restage → 备份 → 确定性改(COPY/set+e) → agent 产循环体 → 写入。

    mode=None → legacy 扁平布局（output/<p>/，glob *_crfuzzer）
    mode='x'  → mode 隔离（output/<p>/x/，glob *_x_crfuzzer，restage 只动本 mode manifest）

    - 备份在任何修改之前、只做一次。
    - COPY、set +e 是确定性机械改动，不经 LLM。
    - 仅「driver 编译循环体」由 agent 生成（它需读原 build.sh 复用 -I/链接库）。
    - 无 DeepSeek 凭证 → 优雅降级：前面 restage/备份/COPY/set+e 已完成，仅编译循环需手补，返回 False。
    - agent 正常提交有效 loop_body 并写入 build.sh → True。
    """
    # 1. restage driver 到构建上下文
    try:
        restage_drivers(project, mode)
    except RuntimeError as e:
        print(f"  [inject] restage 失败: {e}")
        return False

    # 2. 备份（在任何修改之前，只一次）
    session_backup_injectables(project)

    # 3. 确定性修改：Dockerfile COPY + build.sh set +e 头
    print("  [inject]", inject_dockerfile_copy(project, mode))
    print("  [inject]", inject_buildsh_nonfatal_head(project))

    # 4. agent 生成 driver 编译循环体
    if not ac.deepseek_available():
        print("  [inject] 无 DeepSeek 凭证：已完成 restage/备份/COPY/set+e，"
              "但未生成 driver 编译循环。请手补 build.sh 的 dc-injected 尾块，或配置凭证后重试。")
        return False

    handler = _make_inject_handler(project, mode)
    res = ac.run_agent_loop(
        INJECT_SYSTEM_PROMPT, _inject_user_message(project, mode), INJECT_TOOLS, handler,
        model=model, max_steps=max_steps, label="inject",
    )
    payload = res.payload if isinstance(res.payload, dict) else {}
    loop_body = payload.get("loop_body", "") or ""
    if not res.submitted or not loop_body.strip():
        print(f"  [inject] agent 未提交有效编译循环（{res.stop_reason}）；"
              f"已完成 COPY/set+e/备份，建议人工检查 build.sh")
        return False

    # 5. 机械地把循环体包好写进 build.sh 末尾
    print("  [inject]", write_buildsh_driver_loop(project, loop_body))
    print(f"  [inject] 注入完成: {payload.get('reason', '')[:120]}")
    return True


# ══════════════════════════════════════════════════════════════════════
# CLI（调试用：跑单个确定性动作）
# ══════════════════════════════════════════════════════════════════════

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 -m tools.step3_agent.agent_main <project> "
              "[--restage | --backup | --copy | --nonfatal | --build | --diff | --inject] "
              "[--mode focus|peer|cross]")
        sys.exit(1)
    project = sys.argv[1]
    action = "--diff"
    mode = None
    for a in sys.argv[2:]:
        if a.startswith("--mode="):
            mode = a.split("=", 1)[1]
        elif a.startswith("--"):
            action = a

    if action == "--restage":
        restage_drivers(project, mode)
    elif action == "--backup":
        session_backup_injectables(project)
    elif action == "--copy":
        print(inject_dockerfile_copy(project, mode))
    elif action == "--nonfatal":
        print(inject_buildsh_nonfatal_head(project))
    elif action == "--build":
        log = agent_main_build(project, mode=mode)
        print(f"log: {log}")
    elif action == "--inject":
        ok = agent_main_inject(project, mode=mode)
        print(f"inject: {'ok' if ok else 'incomplete'}")
    else:  # --diff
        built, failed = diff_products(project, mode)
        tag = f"[{mode}]" if mode else "[legacy]"
        print(f"project: {project} {tag}")
        print(f"  expected: {len(expected_binaries(project, mode))}")
        print(f"  built:    {len(built)}  {sorted(built)}")
        print(f"  failed:   {len(failed)}  {sorted(failed)}")


if __name__ == "__main__":
    main()