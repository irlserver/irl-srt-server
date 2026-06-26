cmake_minimum_required (VERSION 3.10 FATAL_ERROR)
project(srt-live-server VERSION 3.1.0)

set(CMAKE_CXX_STANDARD 17)

# Emit compile_commands.json for clang-based tooling (clang-tidy, clang-tidy-diff,
# clangd). Honors a caller-supplied -DCMAKE_EXPORT_COMPILE_COMMANDS=OFF; otherwise
# defaults ON so the static-analysis CI job (and local clang-tidy runs) always
# have a compilation database to drive `-p <build-dir>`.
if (NOT DEFINED CMAKE_EXPORT_COMPILE_COMMANDS)
    set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
endif()

# Default to a hardened, optimized Release build when the caller does not pick a
# build type. _FORTIFY_SOURCE (added below) needs -O1 or higher, so an unset
# build type would silently ship without it; Release (-O3) guarantees it is live.
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# --- Compiler-specific flags ---
# -Wsuggest-override / -Woverloaded-virtual catch silent v-table signature drift
# across the CSLSRole hierarchy (a derived override that no longer matches its base
# becomes a NEW virtual instead, silently). Both flags are GCC/Clang only; the
# generic fallback branch keeps the portable base set.
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wsuggest-override -Woverloaded-virtual -Wno-invalid-offsetof -fcompare-debug-second")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wsuggest-override -Woverloaded-virtual -Wno-invalid-offsetof")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wno-invalid-offsetof")
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")

option(SLS_BUILD_TESTS "Build unit tests" OFF)
option(SLS_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(SLS_TSAN "Build with ThreadSanitizer (mutually exclusive with SLS_SANITIZE)" OFF)
option(SLS_COVERAGE "Build with code-coverage instrumentation (gcov/llvm-cov); dedicated build only" OFF)
option(SLS_FUZZ "Build libFuzzer fuzz targets (clang-only; ASan+UBSan); dedicated build only" OFF)

# Coverage instrumentation is a measurement build, never a shipping or sanitizer
# one. Refuse to fuse it with the sanitizers so its flags can never leak into an
# ASan/TSan run, and so it lives in its own dedicated build directory.
if (SLS_COVERAGE AND (SLS_SANITIZE OR SLS_TSAN))
    message(FATAL_ERROR "SLS_COVERAGE is mutually exclusive with SLS_SANITIZE/SLS_TSAN; use a separate coverage build directory.")
endif()

# Fuzzing is its own dedicated, clang-only build flavor. libFuzzer is a Clang
# feature, and its ASan/UBSan + SanitizerCoverage instrumentation must never be
# fused with the other sanitizer/coverage flavors or leak into a shipping build.
if (SLS_FUZZ AND (SLS_SANITIZE OR SLS_TSAN OR SLS_COVERAGE))
    message(FATAL_ERROR "SLS_FUZZ is mutually exclusive with SLS_SANITIZE/SLS_TSAN/SLS_COVERAGE; use a dedicated fuzz build directory.")
endif()
if (SLS_FUZZ AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "SLS_FUZZ requires Clang (libFuzzer is clang-only). Re-run with -DCMAKE_CXX_COMPILER=clang++.")
endif()

if (SLS_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=address,undefined)
endif()
if (SLS_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=thread)
endif()
if (SLS_COVERAGE)
    # GCC's -fcompare-debug-second (set in CMAKE_CXX_FLAGS above to silence
    # duplicate diagnostics) tells the compiler to omit side-effect outputs —
    # which includes the .gcno coverage notes files. Left in, coverage emits
    # .gcda with no matching .gcno and gcov/gcovr fail with "cannot open notes
    # file", so strip it for the coverage build only.
    string(REPLACE "-fcompare-debug-second" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    # --coverage == -fprofile-arcs -ftest-coverage at compile + the gcov runtime
    # at link. -O0 -fno-inline keep line/branch counts faithful to the source.
    # Gated on the option, so a Release build (SLS_COVERAGE=OFF) never carries
    # these flags — coverage instrumentation is not mixed into shipping builds.
    add_compile_options(--coverage -O0 -g -fno-inline)
    add_link_options(--coverage)
endif()
if (SLS_FUZZ)
    # Coverage-guided fuzzing under ASan + UBSan. `fuzzer-no-link` adds the
    # SanitizerCoverage instrumentation (plus ASan/UBSan) to every translation
    # unit WITHOUT injecting a libFuzzer main(), so the ordinary binaries
    # (srt_server, srt_client) still link cleanly; only the targets in
    # tests/fuzz add -fsanitize=fuzzer to pull in the libFuzzer driver + main.
    # Gated on the option, so an ordinary Release/sanitizer/coverage build never
    # carries any of these flags.
    #
    # UBSan is left RECOVERABLE (no -fno-sanitize-recover), matching the
    # project's existing SLS_SANITIZE policy: ASan stays fatal so these targets
    # lock the memory-safety / out-of-bounds hardening the parsers were given
    # (length-driven TS parser, c350a7c), while a pre-existing, benign signed
    # left-shift in the FFmpeg-derived PES PTS extractor (ff_parse_pes_pts in
    # src/core/common.cpp: `(buf[0] & 0x0e) << 29` is evaluated in int before the
    # int64_t cast) is reported but does not abort the run — exactly as it is
    # reported-and-tolerated under SLS_SANITIZE today. We do NOT edit the parser
    # to silence it (task constraint: do not alter parser logic). The finding is
    # documented in tests/fuzz/ubsan_suppressions.txt, which the run command
    # passes via UBSAN_OPTIONS=suppressions=... only to keep the log readable.
    #
    # Drop the Release `-s` strip for this measurement build and pin -O1 -g so
    # libFuzzer can symbolize crashes and the parsers keep faithful bounds.
    set(CMAKE_CXX_FLAGS_RELEASE "-O1 -g")
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# --- Exploit-mitigation / hardening flags ---
# Applied to normal builds only. Sanitizer builds bring their own instrumentation
# and runtime; mixing FORTIFY/CFI/full-RELRO with ASan/TSan adds no security value
# and can confuse their interceptors, so they are skipped under SLS_SANITIZE/SLS_TSAN.
# The coverage build is likewise a non-shipping measurement build (and runs at -O0,
# where FORTIFY is a warning-only no-op), so it is excluded too. The fuzz build is
# a non-shipping ASan/UBSan measurement build as well, so it is excluded for the
# same reason the sanitizer builds are.
if (NOT SLS_SANITIZE AND NOT SLS_TSAN AND NOT SLS_COVERAGE AND NOT SLS_FUZZ)
    # Stack canaries on any function with a local buffer or large stack frame.
    add_compile_options(-fstack-protector-strong)

    # Probe each stack page so a huge frame cannot jump the guard page
    # (stack-clash). GCC and Clang only.
    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-fstack-clash-protection)
    endif()

    # _FORTIFY_SOURCE replaces unbounded libc calls with bounds-checked variants,
    # but it is a no-op (and warns) without optimization. Debug uses -g only, so
    # restrict it to the optimized build types.
    if (CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo|MinSizeRel")
        add_compile_options(-D_FORTIFY_SOURCE=2)
    endif()

    # Control-flow integrity, architecture specific.
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|i686|AMD64")
        add_compile_options(-fcf-protection=full)
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        add_compile_options(-mbranch-protection=standard)
    endif()

    # Position-independent executable so the loader can apply full ASLR.
    add_compile_options(-fPIE)

    # Linker hardening: full RELRO (-z relro -z now => BIND_NOW, GOT read-only),
    # non-executable stack, and emit a PIE.
    add_link_options(-Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include(CTest)
enable_testing()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

add_compile_definitions(SLS_VERSION="${PROJECT_VERSION}")

# Compile out per-packet SPDLOG_TRACE/SPDLOG_DEBUG calls. Only the
# SPDLOG_TRACE(...) / SPDLOG_DEBUG(...) macros respect this; plain
# spdlog::trace(...) function calls still pay the format-arg evaluation
# cost. The hot per-packet sites on the data path use the macro form so
# their argument evaluation is fully stripped here.
add_compile_definitions(SPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO)

# --- External libraries ---
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# spdlog
add_subdirectory(lib/spdlog)

# nlohmann/json
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
add_subdirectory(lib/json)

# cpp-httplib (header-only)
add_library(httplib INTERFACE)
target_include_directories(httplib INTERFACE ${PROJECT_SOURCE_DIR}/lib/cpp-httplib)
target_compile_definitions(httplib INTERFACE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(httplib INTERFACE OpenSSL::SSL OpenSSL::Crypto)

# BS thread pool (header-only)
add_library(BS_thread_pool INTERFACE)
target_include_directories(BS_thread_pool INTERFACE ${PROJECT_SOURCE_DIR}/lib/thread-pool)

# CxxUrl
set(ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(lib/CxxUrl)

# Use SLS Core
add_subdirectory(${PROJECT_SOURCE_DIR}/src)

if (SLS_BUILD_TESTS)
    add_subdirectory(tests)
endif()

# libFuzzer harnesses for the network-boundary parsers (TS / streamid / config).
# Gated on the clang-only SLS_FUZZ option, which also applies the
# fuzzer-no-link/ASan/UBSan instrumentation to sls_core above.
if (SLS_FUZZ)
    add_subdirectory(tests/fuzz)
endif()
