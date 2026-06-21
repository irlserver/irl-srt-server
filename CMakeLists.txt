cmake_minimum_required (VERSION 3.10 FATAL_ERROR)
project(srt-live-server VERSION 3.1.0)

set(CMAKE_CXX_STANDARD 17)

# --- Compiler-specific flags ---
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-invalid-offsetof -fcompare-debug-second")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-invalid-offsetof")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-invalid-offsetof")
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
