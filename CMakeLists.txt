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

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include(CTest)
enable_testing()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

add_compile_definitions(SLS_VERSION="${PROJECT_VERSION}")

# --- External libraries ---
find_package(Threads REQUIRED)

# spdlog
add_subdirectory(lib/spdlog)

# nlohmann/json
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
add_subdirectory(lib/json)

# cpp-httplib (header-only)
add_library(httplib INTERFACE)
target_include_directories(httplib INTERFACE ${PROJECT_SOURCE_DIR}/lib/cpp-httplib)

# BS thread pool (header-only)
add_library(BS_thread_pool INTERFACE)
target_include_directories(BS_thread_pool INTERFACE ${PROJECT_SOURCE_DIR}/lib/thread-pool)


# Use SLS Core
add_subdirectory(${PROJECT_SOURCE_DIR}/src)
