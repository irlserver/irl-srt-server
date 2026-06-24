cmake_minimum_required (VERSION 3.10 FATAL_ERROR)
project(srt-live-server VERSION 3.1.0)

set(CMAKE_CXX_STANDARD 17)

# Default to a hardened, optimized Release build when the caller does not pick a
# build type. _FORTIFY_SOURCE (added below) needs -O1 or higher, so an unset
# build type would silently ship without it; Release (-O3) guarantees it is live.
if (NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# --- Compiler-specific flags ---
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wno-invalid-offsetof -fcompare-debug-second")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wno-invalid-offsetof")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wno-invalid-offsetof")
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")

option(SLS_BUILD_TESTS "Build unit tests" OFF)
option(SLS_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(SLS_TSAN "Build with ThreadSanitizer (mutually exclusive with SLS_SANITIZE)" OFF)

if (SLS_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=address,undefined)
endif()
if (SLS_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=thread)
endif()

# --- Exploit-mitigation / hardening flags ---
# Applied to normal builds only. Sanitizer builds bring their own instrumentation
# and runtime; mixing FORTIFY/CFI/full-RELRO with ASan/TSan adds no security value
# and can confuse their interceptors, so they are skipped under SLS_SANITIZE/SLS_TSAN.
if (NOT SLS_SANITIZE AND NOT SLS_TSAN)
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
