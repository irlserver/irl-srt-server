cmake_minimum_required(VERSION 3.5.0)
project(srt-live-server VERSION 2.5.0)

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
add_subdirectory(${PROJECT_SOURCE_DIR}/lib/spdlog)
find_package(spdlog)

set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(${PROJECT_SOURCE_DIR}/lib/json)

find_package(Threads)

# Use SLS Core
add_subdirectory(${PROJECT_SOURCE_DIR}/src)
