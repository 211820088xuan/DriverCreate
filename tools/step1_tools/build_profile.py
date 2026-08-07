#!/usr/bin/env python3
"""Step1 Section C：构建 Profile 提取 → build_profile.json。"""
# 从 step1_prepare.py 阶段2 拆出（函数体逐字搬运，未改逻辑）

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import json
import os
import re
from config import OSS_FUZZ_DIR, SRC_DIR, VENDOR_SKIP_DIRS, intermediate_for

# ══════════════════════════════════════════════════════════════════════
# Section C: 构建 Profile 提取
# ══════════════════════════════════════════════════════════════════════

def _detect_build_system(src_dir):
    result = {"type": "unknown", "files": []}
    cmake = src_dir / "CMakeLists.txt"
    if cmake.exists():
        result["type"] = "cmake"
        result["files"].append(str(cmake))
        for sub in ["tests/fuzz", "fuzz", "test/fuzz"]:
            p = src_dir / sub / "CMakeLists.txt"
            if p.exists():
                result["files"].append(str(p))

    configure = src_dir / "configure"
    configure_ac = src_dir / "configure.ac"
    makefile_am = src_dir / "Makefile.am"
    if configure.exists() or (configure_ac.exists() and makefile_am.exists()):
        result["type"] = "autotools"
        if configure_ac.exists():
            result["files"].append(str(configure_ac))
        if makefile_am.exists():
            result["files"].append(str(makefile_am))
        for sub in ["fuzz", "tests/fuzz"]:
            p = src_dir / sub / "Makefile.am"
            if p.exists():
                result["files"].append(str(p))

    meson = src_dir / "meson.build"
    if meson.exists():
        result["type"] = "meson"
        result["files"].append(str(meson))

    makefiles = list(src_dir.glob("Makefile*"))
    if makefiles and result["type"] == "unknown":
        result["type"] = "makefile"
        result["files"].extend(str(m) for m in makefiles[:3])
    return result


def _extract_from_cmake(src_dir, profile):
    cmake_file = src_dir / "CMakeLists.txt"
    content = cmake_file.read_text()

    if "FetchContent" in content:
        profile["has_fetchcontent"] = True
        deps = re.findall(r'FetchContent_Declare\s*\(\s*(\w+)', content)
        known_deps = {
            "zlib": "ZLIB", "zlib_ng": "ZLIB", "zstd": "ZSTD", "lz4": "LZ4",
            "snappy": "SNAPPY", "bzip2": "BZIP2", "xz": "XZ",
            "gtest": "GTEST", "benchmark": "BENCHMARK", "catch2": "CATCH2",
        }
        for dep in deps:
            normalized = known_deps.get(dep.lower())
            if normalized:
                profile.setdefault("cmake_flags", "")
                for flag in [f"-DDEACTIVATE_{normalized}=ON", f"-DPREFER_EXTERNAL_{normalized}=ON"]:
                    if flag not in profile["cmake_flags"]:
                        profile["cmake_flags"] += f" {flag}"

    for m in re.findall(r'option\((\w+)\s+"([^"]*)"', content):
        name, desc = m
        if 'fuzz' in name.lower() or 'fuzz' in desc.lower():
            profile.setdefault("cmake_fuzz_options", {})[name] = desc

    pkgs = re.findall(r'(?:find_package|pkg_check_modules)\s*\((\w+)', content)
    if pkgs:
        profile.setdefault("cmake_dependencies", []).extend(pkgs)

    default_flags = ("-DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF "
                     "-DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF "
                     "-DBUILD_EXAMPLES=OFF -DBUILD_FUZZERS=OFF -DBUILD_PLUGINS=OFF")
    existing = profile.get("cmake_flags", "")
    profile["cmake_flags"] = (default_flags + " " + existing).strip()


def _extract_from_autotools(src_dir, profile):
    fuzz_makefile = None
    for p in [src_dir / "fuzz" / "Makefile.am", src_dir / "tests" / "fuzz" / "Makefile.am"]:
        if p.exists():
            fuzz_makefile = p
            break

    if fuzz_makefile:
        content = fuzz_makefile.read_text()
        for var_name, key in [('AM_CPPFLAGS', 'auto_cppflags'), ('AM_CFLAGS', 'auto_cflags'),
                               ('AM_CXXFLAGS', 'auto_cxxflags'), ('LDADD', 'auto_ldadd')]:
            m = re.findall(rf'{var_name}\s*=\s*(.+?)(?:\n|$)', content)
            if m:
                profile[key] = m[0].strip()

        if "configure_flags" not in profile:
            profile["configure_flags"] = "--enable-static --disable-shared"

    configure_ac = src_dir / "configure.ac"
    if configure_ac.exists():
        for m in re.findall(r'AC_ARG_ENABLE\(\[(\w+)\]', configure_ac.read_text()):
            if 'fuzz' in m.lower() or 'static' in m.lower() or 'shared' in m.lower():
                profile.setdefault("configure_flags_raw", []).append(m)


def _scan_include_dirs(src_dir, template_data):
    dirs = []
    includes = template_data.get("common_includes", []) or template_data.get("all_includes", [])

    for inc in includes:
        header = inc.strip('<>"')
        for root, subdirs, files in os.walk(str(src_dir)):
            depth = root.replace(str(src_dir), "").count(os.sep)
            if depth > 5:
                subdirs.clear()
                continue
            if header in files:
                rel = os.path.relpath(root, src_dir)
                d = "$SRC" if rel == "." else f"$SRC/{rel}"
                if d not in dirs:
                    dirs.append(d)

    # 兜底候选目录：常规头目录 + 库内部头目录（library/core/crypto/common 等）。
    # mbedtls 这类把 common.h 放在 library/ 的项目，官方走 CMake 全量构建会自动带上，
    # 但单文件注入编译需显式补 -I，否则 'common.h' file not found。
    for c in ["include", "includes", "inc", "src/include", "src", "lib", "src/lib",
              "library", "core", "crypto", "common", "public", "api"]:
        p = src_dir / c
        if p.is_dir() and (any(p.glob("*.h")) or any(p.glob("*/*.h"))):
            d = f"$SRC/{c}"
            if d not in dirs:
                dirs.append(d)

    # 过滤 private/internal + vendor/platform 目录
    dirs = [d for d in dirs if not any(
        skip in d.lower() for skip in ['/private', '/internal', '/detail', '/impl']
    ) and not any(
        f'/{vendor_dir}' in d or d.endswith(f'/{vendor_dir}')
        for vendor_dir in VENDOR_SKIP_DIRS
    )]
    return dirs if dirs else ["$SRC"]


def _map_headers_to_libs(template_data):
    header_to_pkg = {
        # 压缩
        "zlib.h": ("zlib1g-dev", "-lz"), "zstd.h": ("libzstd-dev", "-lzstd"),
        "lz4.h": ("liblz4-dev", "-llz4"), "lz4frame.h": ("liblz4-dev", "-llz4"),
        "bzlib.h": ("libbz2-dev", "-lbz2"), "lzma.h": ("liblzma-dev", "-llzma"),
        "brotli/decode.h": ("libbrotli-dev", "-lbrotlidec"),
        # 网络 / 抓包
        "pcap.h": ("libpcap-dev", "-lpcap"), "pcap/pcap.h": ("libpcap-dev", "-lpcap"),
        "curl/curl.h": ("libcurl4-openssl-dev", "-lcurl"),
        # 加密 / TLS
        "ssl.h": ("libssl-dev", "-lssl"), "openssl/ssl.h": ("libssl-dev", "-lssl"),
        "crypto.h": ("libssl-dev", "-lcrypto"), "openssl/crypto.h": ("libssl-dev", "-lcrypto"),
        # XML / 解析
        "xml2.h": ("libxml2-dev", "-lxml2"), "libxml/parser.h": ("libxml2-dev", "-lxml2"),
        "expat.h": ("libexpat1-dev", "-lexpat"),
        # 图像
        "jpeglib.h": ("libjpeg-dev", "-ljpeg"), "png.h": ("libpng-dev", "-lpng"),
        "tiffio.h": ("libtiff-dev", "-ltiff"),
        # 字体 / 文本整形（harfbuzz 依赖 freetype，缺 -lfreetype 会链接失败）
        "ft2build.h": ("libfreetype6-dev", "-lfreetype"),
        "freetype/freetype.h": ("libfreetype6-dev", "-lfreetype"),
        "hb.h": ("libharfbuzz-dev", "-lharfbuzz"), "harfbuzz/hb.h": ("libharfbuzz-dev", "-lharfbuzz"),
        # 其它常见
        "pthread.h": (None, "-lpthread"),
        "unicode/utypes.h": ("libicu-dev", "-licuuc"),
    }
    sys_deps, sys_libs = [], []
    seen_deps, seen_libs = set(), set()
    for inc in template_data.get("all_includes", []):
        header = inc.strip('<>"')
        if header in header_to_pkg:
            dep, lib = header_to_pkg[header]
            if dep and dep not in seen_deps:
                sys_deps.append(dep); seen_deps.add(dep)
            if lib and lib not in seen_libs:
                sys_libs.append(lib); seen_libs.add(lib)
    return {"sys_deps": " ".join(sys_deps) if sys_deps else "",
            "sys_libs": " ".join(sys_libs) if sys_libs else ""}


def _detect_cxx_standard(project, src_dir):
    """检测项目强制的 C++ 标准（从 Makefile.am, CMakeLists.txt, build.sh）

    返回:
        {
            "detected": "c++11" | "c++14" | "c++17" | None,
            "source": "Makefile.am" | "CMakeLists.txt" | "build.sh" | None,
            "allow_fdp": bool  # FuzzedDataProvider 是否可用（需要 C++14+）
        }
    """
    result = {"detected": None, "source": None, "allow_fdp": True}

    # 1. 检查 OSS-Fuzz 的 Makefile.am（最高优先级）
    oss_fuzz_makefile = src_dir / "oss-fuzz" / "Makefile.am"
    if oss_fuzz_makefile.exists():
        try:
            content = oss_fuzz_makefile.read_text(errors='ignore')
            match = re.search(r'-std=(c\+\+\d+|gnu\+\+\d+)', content)
            if match:
                std = match.group(1).replace('gnu++', 'c++')
                result["detected"] = std
                result["source"] = "oss-fuzz/Makefile.am"
                result["allow_fdp"] = std not in ['c++98', 'c++03', 'c++11']
                return result
        except Exception:
            pass

    # 2. 检查根目录 Makefile.am
    makefile_am = src_dir / "Makefile.am"
    if makefile_am.exists():
        try:
            content = makefile_am.read_text(errors='ignore')
            match = re.search(r'-std=(c\+\+\d+|gnu\+\+\d+)', content)
            if match:
                std = match.group(1).replace('gnu++', 'c++')
                result["detected"] = std
                result["source"] = "Makefile.am"
                result["allow_fdp"] = std not in ['c++98', 'c++03', 'c++11']
                return result
        except Exception:
            pass

    # 3. 检查 CMakeLists.txt（CMAKE_CXX_STANDARD 或 set_property）
    cmake_file = src_dir / "CMakeLists.txt"
    if cmake_file.exists():
        try:
            content = cmake_file.read_text(errors='ignore')
            match = re.search(r'CMAKE_CXX_STANDARD\s+(\d+)', content)
            if match:
                std_num = match.group(1)
                result["detected"] = f"c++{std_num}"
                result["source"] = "CMakeLists.txt"
                result["allow_fdp"] = int(std_num) >= 14
                return result
            match = re.search(r'CXX_STANDARD\s+(\d+)', content)
            if match:
                std_num = match.group(1)
                result["detected"] = f"c++{std_num}"
                result["source"] = "CMakeLists.txt"
                result["allow_fdp"] = int(std_num) >= 14
                return result
        except Exception:
            pass

    # 4. 检查 OSS-Fuzz 的 build.sh（CXXFLAGS 覆盖）
    oss_fuzz_dir = OSS_FUZZ_DIR / "projects" / project
    build_sh = oss_fuzz_dir / "build.sh"
    if build_sh.exists():
        try:
            content = build_sh.read_text(errors='ignore')
            match = re.search(r'CXXFLAGS.*-std=(c\+\+\d+|gnu\+\+\d+)', content)
            if match:
                std = match.group(1).replace('gnu++', 'c++')
                result["detected"] = std
                result["source"] = "oss-fuzz/build.sh"
                result["allow_fdp"] = std not in ['c++98', 'c++03', 'c++11']
                return result
        except Exception:
            pass

    # 5. 未检测到显式配置，假定使用编译器默认
    result["detected"] = None
    result["source"] = None
    result["allow_fdp"] = True
    return result


def run_build_profile(project, template_data):
    """Step C: 构建 Profile 提取 → build_profile.json"""
    print("\n--- 构建 Profile ---")
    src_dir = SRC_DIR / project
    if not src_dir.exists():
        print(f"  错误: 源码目录 {src_dir} 不存在")
        return None

    profile = {"project": project, "build_system": "unknown",
               "include_dirs": [], "sys_deps": "", "sys_libs": "",
               "preferred_compiler": "clang"}

    build = _detect_build_system(src_dir)
    profile["build_system"] = build["type"]
    print(f"  构建系统: {build['type']}")

    if build["type"] == "autotools":
        _extract_from_autotools(src_dir, profile)
    elif build["type"] == "cmake":
        _extract_from_cmake(src_dir, profile)

    profile["include_dirs"] = _scan_include_dirs(src_dir, template_data)
    print(f"  include: {profile['include_dirs']}")

    lib_info = _map_headers_to_libs(template_data)
    profile["sys_deps"] = lib_info["sys_deps"] or "liblz4-dev libzstd-dev zlib1g-dev"
    profile["sys_libs"] = lib_info["sys_libs"] or "-llz4 -lzstd -lz"
    print(f"  sys_deps: {profile['sys_deps']}")
    print(f"  sys_libs: {profile['sys_libs']}")

    # 编译器偏好
    lang = template_data.get("dominant_lang", "c")
    cpp_count = c_count = 0
    for root, _, files in os.walk(str(src_dir)):
        if root.replace(str(src_dir), "").count(os.sep) > 3:
            continue
        for f in files:
            if f.endswith(('.cpp', '.cc', '.cxx')):
                cpp_count += 1
            elif f.endswith('.c'):
                c_count += 1
    profile["preferred_compiler"] = "clang++" if (lang == "cpp" or cpp_count > c_count * 0.3) else "clang"
    print(f"  compiler: {profile['preferred_compiler']}")

    # 检测 C++ 标准约束
    cxx_std = _detect_cxx_standard(project, src_dir)
    profile["cxx_standard"] = cxx_std["detected"]
    profile["cxx_std_source"] = cxx_std["source"]
    profile["allow_fuzzed_data_provider"] = cxx_std["allow_fdp"]
    if cxx_std["detected"]:
        print(f"  C++ 标准: {cxx_std['detected']} (来源: {cxx_std['source']})")
        if not cxx_std["allow_fdp"]:
            print(f"    ⚠️  FuzzedDataProvider 不可用（需要 C++14+）")

    out_path = intermediate_for(project) / "build_profile.json"
    out_path.write_text(json.dumps(profile, indent=2, ensure_ascii=False))
    print(f"  → {out_path}")
    return profile
