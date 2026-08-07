#!/usr/bin/env python3
"""Step2 校验器：include 白名单 / 函数调用臆造检测 / 类型可见性 / 平台头。"""
# 从 step2_generate.py 阶段3 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import os
import re
from config import INTERMEDIATE_DIR, SRC_DIR
from tools.step2_tools.signature_cache import _sig_names, extract_helper_signatures

C_KW = {'if','for','while','switch','return','sizeof','void','int','char',
        'const','static','unsigned','signed','long','short','double','float',
        'goto','break','continue','case','default','struct','union','enum','typedef',
        'PREFIX','ARRAY_SIZE','Z_UNUSED','MIN','MAX'}

def _is_private_header(name: str) -> bool:
    """判断一个源码根目录下的 .h 是否是「项目私有/内部头」，不应让 driver 直接 include。

    这类头通常是构建期由 configure/cmake 生成、依赖 HAVE_* 宏或内部编译单元上下文，
    外部单独 include 会触发 `#error`（如 json-c 的 vasprintf_compat.h/snprintf_compat.h
    顶部 `#error snprintf is required but was not found`）或暴露不该用的内部符号。

    仅用通用命名约定（不针对任何具体项目），宁可漏判（放行）不误伤公开 API 头：
      - *_compat.h / *_internal.h / *_private.h / *_priv.h  → 私有
      - config.h / *config.h / *_config.h                  → 构建期生成配置头
    公开 umbrella header（如 json.h）与项目名同名头一律不受影响。
    """
    stem = name[:-2] if name.endswith(".h") else name
    stem = stem.lower()
    for suf in ("_compat", "_internal", "_private", "_priv", "_impl"):
        if stem.endswith(suf):
            return True
    if stem == "config" or stem.endswith("config"):
        return True
    return False


def build_include_whitelist(project):
    """从 fuzzing_headers.json + 标准库构建 include 白名单。"""
    allowed = set()
    fh_path = INTERMEDIATE_DIR / project / "fuzzing_headers.json"
    if fh_path.exists():
        try:
            fh_data = json.loads(fh_path.read_text())
            for h in fh_data.get("required_headers", []):
                allowed.add(Path(h["path"]).name)
            for h in fh_data.get("optional_headers", []):
                allowed.add(Path(h["path"]).name)
            for h in fh_data.get("standard_or_api_headers", []):
                allowed.add(Path(h).name)
        except Exception:
            pass

    src_inc = SRC_DIR / project / "include"
    if src_inc.exists():
        for f in src_inc.rglob("*.h"):
            allowed.add(f.name)
    src_root = SRC_DIR / project
    if src_root.exists():
        for f in src_root.glob("*.h"):
            if _is_private_header(f.name):
                continue
            allowed.add(f.name)

    allowed.update([
        "stddef.h", "stdint.h", "stdlib.h", "stdio.h", "string.h",
        "stdbool.h", "time.h", "limits.h", "assert.h", "math.h",
        "errno.h", "float.h", "inttypes.h", "signal.h", "unistd.h",
        "fcntl.h", "sys/types.h", "sys/stat.h", "memory.h", "setjmp.h",
        "stdarg.h",  # 可变参数（va_list/va_start/va_end）
        "cstring", "cstdlib", "cstdio", "cstdint", "cassert", "climits",
        "cmath", "cstddef", "iostream", "fstream", "sstream", "vector",
        "string", "memory", "algorithm", "functional", "map", "set",
        "unordered_map", "unordered_set", "array", "ctime", "cerrno",
        "csetjmp", "csignal", "numeric", "iterator", "utility", "tuple",
        "cstdarg",  # C++ 可变参数
        "fuzzer/FuzzedDataProvider.h", "FuzzedDataProvider.h",  # libFuzzer 标准 C++ helper
    ])
    return allowed


def validate_driver_includes(code, project):
    """检查 driver 代码的 #include 是否都在白名单内。"""
    whitelist = build_include_whitelist(project)
    if not whitelist:
        return True, []

    violations = []
    for line in code.splitlines():
        line = line.strip()
        m = re.match(r'^\s*#include\s+[<"]([^>"]+)[>"]', line)
        if not m:
            continue
        header = m.group(1)
        basename = Path(header).name
        if basename not in whitelist and header not in whitelist:
            violations.append(header)
    return len(violations) == 0, violations


# ─── Block B: 函数调用硬验证器 ─────────────────────────────────────

_STDLIB_C = {
    'memcpy','memmove','memcmp','memset','memchr','memmem',
    'strcmp','strncmp','strcasecmp','strncasecmp','strlen','strnlen',
    'strdup','strndup','strchr','strrchr','strstr','strspn','strcspn',
    'strpbrk','strtok','strtok_r','strcpy','strncpy','strcat','strncat',
    'strerror','strerror_r','strsignal',
    'malloc','calloc','realloc','free','aligned_alloc','posix_memalign',
    'printf','fprintf','sprintf','snprintf','asprintf','vprintf','vfprintf',
    'vsprintf','vsnprintf','fputs','fputc','putchar','puts',
    'scanf','fscanf','sscanf','vscanf','vfscanf','vsscanf',
    'fgets','fgetc','getchar','gets','ungetc',
    'fread','fwrite','fopen','freopen','fclose','fflush','fseek','ftell',
    'rewind','fseeko','ftello','fileno','feof','ferror','clearerr','setvbuf',
    'abort','exit','_Exit','atexit','abort','raise','signal','kill',
    'atoi','atol','atoll','atof','strtol','strtoll','strtoul','strtoull',
    'strtof','strtod','strtold',
    'abs','labs','llabs','div','ldiv','lldiv',
    'qsort','bsearch','rand','srand',
    'pow','sqrt','cbrt','exp','log','log2','log10','sin','cos','tan',
    'asin','acos','atan','atan2','sinh','cosh','tanh',
    'floor','ceil','round','trunc','fmod','fabs','fmax','fmin','hypot',
    'isnan','isinf','isfinite','isnormal',
    'isdigit','isalpha','isalnum','isspace','isprint','iscntrl','ispunct',
    'isupper','islower','isxdigit','isascii',
    'tolower','toupper',
    'time','clock','gettimeofday','difftime','mktime','localtime','gmtime',
    'strftime','strptime','asctime','ctime',
    'getenv','setenv','unsetenv','putenv','system','getpid','getppid',
    'geteuid','getuid','getegid','getgid','getcwd','chdir',
    'read','write','close','open','openat','creat','pread','pwrite',
    'lseek','fcntl','ioctl','dup','dup2','pipe','poll','select',
    'mmap','munmap','mprotect','madvise','msync','mlock','munlock','brk','sbrk',
    'stat','fstat','lstat','access','chmod','chown','umask','unlink','rename',
    'mkdir','rmdir','symlink','readlink','link',
    'setjmp','longjmp','sigsetjmp','siglongjmp',
    'assert','__assert_fail',
    'errno','strerror',
    'getopt','getopt_long',
    # 临时文件/目录（fuzz driver 常用：写数据到临时文件再读）
    'mkstemp','mkstemps','mkdtemp','mkostemp','mkostemps',
    'tmpfile','tmpnam','tempnam','tmpfile64','tmpnam_r',
    # 栈分配 / 字符串扩展（BSD/glibc 常用）
    'alloca','strdupa','strndupa','strlcpy','strlcat','memccpy',
    'stpcpy','stpncpy','strcasestr','strsep','strchrnul','strnlen',
    'basename','dirname',
    # 进程 / 信号
    'fork','vfork','_exit','waitpid','wait','waitid','wait4',
    'execl','execlp','execv','execvp','execve','execlpe','execvpe',
    'sigaction','sigemptyset','sigfillset','sigaddset','sigdelset',
    'sigprocmask','sigpending','sigsuspend','sigwait','sigwaitinfo',
    'killpg','setpgid','getpgid','setsid','getsid','prctl',
    # 时间 / 睡眠
    'clock_gettime','clock_settime','clock_nanosleep','nanosleep','sleep','usleep',
    # 目录流
    'opendir','readdir','readdir_r','closedir','rewinddir','telldir','seekdir',
    'scandir','alphasort','dirfd',
    # IO 补充
    'perror','dprintf','vdprintf','getline','getdelim','popen','pclose',
    'fdatasync','fsync','flock','fileno',
    # 路径
    'realpath','canonicalize_file_name',
    # 用户/组
    'getpwuid','getpwnam','getgrgid','getgrnam','getlogin','getlogin_r',
    # 终端
    'isatty','ttyname','ttyname_r','ctermid','tcgetattr','tcsetattr',
    # 宽字符（部分 driver 用）
    'wprintf','wscanf','fwprintf','fwscanf','swprintf','swscanf',
    'wcslen','wcscpy','wcsncpy','wcscat','wcsncat','wcscmp','wcsncmp',
    'wcschr','wcsrchr','wcsstr','wcstombs','mbstowcs','wctomb','mbtowc',
    'btowc','wctob',
    # 大文件 / off_t
    'fopen64','freopen64','fseeko64','ftello64','stat64','fstat64','lstat64',
    'open64','creat64','lseek64','mmap64','pread64','pwrite64',
    # 杂项常用
    'htonl','htons','ntohl','ntohs','be32toh','be16toh','le32toh','le16toh',
    'inet_pton','inet_ntop','inet_addr','inet_ntoa',
    'getaddrinfo','freeaddrinfo','getnameinfo','socket','connect','bind',
    'listen','accept','send','recv','sendto','recvfrom','sendmsg','recvmsg',
    'shutdown','setsockopt','getsockopt','getsockname','getpeername',
}
_STDLIB_CPP = {
    'push_back','emplace_back','pop_back','push_front','emplace_front','pop_front',
    'begin','end','cbegin','cend','rbegin','rend','crbegin','crend',
    'size','length','empty','max_size','capacity','reserve','resize','shrink_to_fit',
    'clear','insert','emplace','emplace_hint','erase','swap','assign',
    'front','back','at','data','c_str',
    'find','count','contains','lower_bound','upper_bound','equal_range',
    'substr','append','compare','starts_with','ends_with','replace',
    'move','forward','make_pair','make_shared','make_unique','make_tuple',
    'get','tie','ignore',
    'to_string','stoi','stol','stoll','stoul','stoull','stof','stod',
    'sort','stable_sort','partial_sort','nth_element','partition',
    'copy','copy_n','copy_if','move_backward','fill','fill_n','generate',
    'transform','for_each','accumulate','reduce','partial_sum',
    'min','max','minmax','clamp','all_of','any_of','none_of','equal',
    'lexicographical_compare','includes','set_difference','set_intersection',
    'set_union','merge',
    'unique','remove','remove_if','reverse','rotate','shuffle',
    'lock','unlock','try_lock','lock_guard','unique_lock','scoped_lock',
}
_BUILTINS_PREFIXES = ('__builtin_', '__sync_', '__atomic_')
_BUILTINS = {
    'sizeof','alignof','offsetof','typeof','__typeof__','defined',
    'static_assert','_Static_assert','_Alignas','_Alignof','_Generic',
    'asm','__asm__','__attribute__','__extension__','__inline__','__restrict__',
    '_Pragma','__PRETTY_FUNCTION__','__func__','__FUNCTION__',
    'va_start','va_end','va_arg','va_copy',
    'setjmp','longjmp',
}
_DECL_KW = {
    'extern','namespace','template','struct','union','class','enum','typedef',
    'case','catch','throw','new','delete','goto','using','operator',
    'public','private','protected','virtual','override','final','explicit',
    'friend','mutable','volatile','constexpr','constinit','consteval',
    'noexcept','decltype','nullptr','true','false','this',
}

# Platform-specific headers (OSS-Fuzz only supports Linux/POSIX)
_PLATFORM_SPECIFIC_HEADERS = {
    'windows/': 'Windows-specific path',
    'win32/': 'Windows-specific path',
    '<crtdefs.h>': 'MSVC-specific header (Windows)',
    '<windows.h>': 'Windows API header',
    '<winbase.h>': 'Windows API header',
    '<windef.h>': 'Windows API header',
    '<io.h>': 'MSVC I/O header (use <unistd.h> on Linux)',
    '<direct.h>': 'MSVC directory header (use <unistd.h> on Linux)',
}


def _strip_noncode(code):
    """状态机剥离行/块注释、字符串/字符字面量，用空格保留行号。"""
    out = []
    i, n = 0, len(code)
    state = 'code'  # 'code' | 'line_comment' | 'block_comment' | 'string' | 'char'
    while i < n:
        c = code[i]
        nxt = code[i+1] if i+1 < n else ''
        if state == 'code':
            if c == '/' and nxt == '/':
                out.append('  '); state = 'line_comment'; i += 2; continue
            if c == '/' and nxt == '*':
                out.append('  '); state = 'block_comment'; i += 2; continue
            if c == '"':
                out.append(' '); state = 'string'; i += 1; continue
            if c == "'":
                out.append(' '); state = 'char'; i += 1; continue
            out.append(c); i += 1; continue
        if state == 'line_comment':
            if c == '\n':
                out.append('\n'); state = 'code'
            else:
                out.append(' ' if c != '\t' else '\t')
            i += 1; continue
        if state == 'block_comment':
            if c == '*' and nxt == '/':
                out.append('  '); state = 'code'; i += 2; continue
            out.append('\n' if c == '\n' else (' ' if c != '\t' else '\t'))
            i += 1; continue
        if state == 'string':
            if c == '\\' and nxt:
                out.append('  '); i += 2; continue
            if c == '"':
                out.append(' '); state = 'code'; i += 1; continue
            out.append('\n' if c == '\n' else ' ')
            i += 1; continue
        if state == 'char':
            if c == '\\' and nxt:
                out.append('  '); i += 2; continue
            if c == "'":
                out.append(' '); state = 'code'; i += 1; continue
            out.append('\n' if c == '\n' else ' ')
            i += 1; continue
    return ''.join(out)


def build_call_whitelist(project, sig_cache, fh_data):
    """构建函数调用白名单和黑名单。

    Returns:
        (allowed: set[str], blacklisted: set[str], helper_macros: set[str])
    """
    allowed = set()

    # 1. sig_cache 里的所有函数名（headers 全扫的超集）
    sig_funcs = _sig_names(sig_cache)
    if isinstance(sig_funcs, dict):
        allowed |= set(sig_funcs.keys())
    else:
        allowed |= set(sig_funcs)

    # 2. scored.json 的项目 API
    scored_path = INTERMEDIATE_DIR / project / "scored.json"
    if scored_path.exists():
        try:
            scored = json.loads(scored_path.read_text())
            for item in scored.get("scored_apis", []):
                allowed.add(item["api"])
        except Exception:
            pass

    # 3. Helper 函数/宏（从 fuzzing_headers.json content_preview 提取）
    helper_macros = set()
    if fh_data:
        helper_sigs = extract_helper_signatures(fh_data)
        for hname, sigs in helper_sigs.items():
            for s in sigs:
                # 提取所有可能的名字：先抓 #define / typedef，再抓函数
                m = re.match(r'^#define\s+([A-Za-z_]\w*)', s)
                if m:
                    allowed.add(m.group(1))
                    helper_macros.add(m.group(1))
                    continue
                m = re.match(r'^typedef\s+.*?\b([A-Za-z_]\w*)\s*;?\s*$', s)
                if m:
                    allowed.add(m.group(1))
                    continue
                # 函数：抓 `name(` 前的最后一个 identifier
                for fm in re.finditer(r'\b([A-Za-z_]\w*)\s*\(', s):
                    allowed.add(fm.group(1))

    # 4. 内置集
    allowed |= _STDLIB_C
    allowed |= _STDLIB_CPP
    allowed |= _BUILTINS
    allowed |= _DECL_KW
    allowed |= C_KW

    blacklisted = set()

    return allowed, blacklisted, helper_macros


_CALL_RE = re.compile(r'(?<![\w.>:])([A-Za-z_][A-Za-z_0-9]*)\s*\(')

# 类型使用硬验证 —— 类型可见性（基于 include 传递闭包）
# 匹配两类类型使用：xxx_t 惯例命名 + 显式 struct/union/enum Tag
_TYPE_USE_RE = re.compile(
    r'\b([a-z_][a-z0-9_]*_t)\b'                      # 组1: xxx_t 惯例类型
    r'|(?:struct|union|enum)\s+([A-Za-z_]\w*)'       # 组2: struct/union/enum 标签
)

# C/C++ 标准库类型白名单（永久豁免，不参与可见性验证）
_STDLIB_TYPES = frozenset({
    'size_t', 'ssize_t', 'ptrdiff_t', 'intptr_t', 'uintptr_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int_least8_t', 'int_least16_t', 'int_least32_t', 'int_least64_t',
    'uint_least8_t', 'uint_least16_t', 'uint_least32_t', 'uint_least64_t',
    'int_fast8_t', 'int_fast16_t', 'int_fast32_t', 'int_fast64_t',
    'uint_fast8_t', 'uint_fast16_t', 'uint_fast32_t', 'uint_fast64_t',
    'intmax_t', 'uintmax_t', 'wchar_t', 'char16_t', 'char32_t',
    'wint_t', 'sig_atomic_t', 'time_t', 'clock_t', 'off_t',
    'mode_t', 'pid_t', 'uid_t', 'gid_t', 'fpos_t', 'div_t', 'ldiv_t',
    'va_list', 'jmp_buf', 'sigjmp_buf', 'FILE', 'DIR', 'bool',
    'max_align_t', 'nullptr_t', 'byte',
})


def _reachable_headers(include_graph, entry_headers):
    """从 driver 的 include 集出发，计算项目头文件的传递可达闭包。"""
    seen = set()
    stack = list(entry_headers)
    while stack:
        h = stack.pop()
        if h in seen:
            continue
        seen.add(h)
        for nxt in include_graph.get(h, []):
            if nxt not in seen:
                stack.append(nxt)
    return seen


def validate_driver_types(code, project, sig_cache):
    """硬验证：driver 用的类型必须从其 include 的公开头「传递可达」。

    保守策略（假阳性零容忍）：
      - 只拦「有已知定义头、但该头不在 include 传递闭包内」的类型（高置信）
      - 只查 xxx_t 惯例命名 + 显式 struct/union/enum X
      - 标准库类型豁免；无定义头记录的类型不拦（可能是局部/模板/宏类型）

    Returns:
        (ok: bool, invisible_types: set[str])
    """
    type_headers = sig_cache.get("type_headers", {}) if isinstance(sig_cache, dict) else {}
    include_graph = sig_cache.get("include_graph", {}) if isinstance(sig_cache, dict) else {}
    if not type_headers or not include_graph:
        return True, set()  # 原料缺失，不拦（保守）

    stripped = _strip_noncode(code)

    # driver 自己写的 include（在原始 code 上提取——_strip_noncode 会把 "xxx.h"
    # 当字符串字面量清空，只剩 <> 形式，故必须用原始 code）
    driver_includes = set()
    for m in re.finditer(r'#\s*include\s+[<"]([^>"]+)[>"]', code):
        driver_includes.add(os.path.basename(m.group(1)))

    # 从 driver include 出发算传递闭包
    visible = _reachable_headers(include_graph, driver_includes)

    invisible_types = set()
    for m in _TYPE_USE_RE.finditer(stripped):
        t = m.group(1) or m.group(2)
        if not t or t in _STDLIB_TYPES or t.startswith('__'):
            continue
        defining_header = type_headers.get(t)
        # 只拦：有定义头（真实存在）但不可见（不在闭包）
        if defining_header and defining_header not in visible:
            invisible_types.add(t)

    return (not invisible_types), invisible_types


# libFuzzer 入口/回调函数：driver 自己定义（非调用），validator 永久豁免。
_ENTRY_FUNCS = frozenset({
    "LLVMFuzzerTestOneInput",
    "LLVMFuzzerInitialize",
    "LLVMFuzzerCustomMutator",
    "LLVMFuzzerCustomCrossOver",
})


def _load_fh_data(project):
    """加载 fuzzing_headers.json，找不到返回 None。"""
    fh_path = INTERMEDIATE_DIR / project / "fuzzing_headers.json"
    if not fh_path.exists():
        return None
    try:
        return json.loads(fh_path.read_text())
    except Exception:
        return None


def validate_platform_headers(code):
    """检查代码中是否包含平台特定头文件 (OSS-Fuzz 只支持 Linux/POSIX)。

    Returns:
        (ok: bool, violations: list[str])
    """
    violations = []
    for line_no, line in enumerate(code.splitlines(), 1):
        # 只检查 #include 行
        if not re.match(r'^\s*#\s*include', line):
            continue

        for pattern, reason in _PLATFORM_SPECIFIC_HEADERS.items():
            if pattern in line:
                violations.append(f"L{line_no}: {line.strip()} → {reason}")

    return len(violations) == 0, violations


def validate_driver_calls(code, project, sig_cache, fh_data):
    """扫描 driver 里所有 ident( 形式的调用，判定臆造/黑名单。

    Returns:
        (ok: bool, fake_calls: set[str], blacklisted_hits: set[str])
    """
    allowed, blacklisted, helper_macros = build_call_whitelist(project, sig_cache, fh_data)

    stripped = _strip_noncode(code)

    fake_calls = set()
    blk_hits = set()

    for m in _CALL_RE.finditer(stripped):
        ident = m.group(1)
        start = m.start(1)

        # 跳过：语句关键字/内置
        if ident in _BUILTINS or ident in _DECL_KW or ident in C_KW:
            continue
        if ident.startswith(_BUILTINS_PREFIXES):
            continue

        # 跳过：libFuzzer 入口/回调函数（driver 自己定义，非调用；永久豁免）
        if ident in _ENTRY_FUNCS:
            continue

        # 跳过：宏定义左值（当前行 `#define NAME(...)`）
        line_start = stripped.rfind('\n', 0, start) + 1
        line_end = stripped.find('\n', start)
        cur_line = stripped[line_start: line_end if line_end != -1 else len(stripped)].strip()
        if cur_line.startswith('#define ') or cur_line.startswith('#define\t'):
            # 检查是不是"当前 ident 就是被定义的宏名"
            after_define = cur_line[len('#define'):].lstrip()
            if after_define.startswith(ident):
                continue

        # 跳过：函数指针解引用调用 —— 前一非空白字符是 * & (
        p = start - 1
        while p >= 0 and stripped[p] in ' \t':
            p -= 1
        if p >= 0 and stripped[p] in '*&(':
            continue

        # 命中黑名单优先（即使 sig_cache 里有）
        if ident in blacklisted:
            blk_hits.add(ident)
            continue

        # 全大写 helper 宏放行
        if ident.isupper() and ident in helper_macros:
            continue

        # 白名单命中放行
        if ident in allowed:
            continue

        # 都不命中 → 臆造
        fake_calls.add(ident)

    ok = not fake_calls  # 只检查臆造
    return ok, fake_calls, blk_hits


