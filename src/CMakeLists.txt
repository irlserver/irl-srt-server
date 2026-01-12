add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/core)

add_executable(srt_server ${CMAKE_CURRENT_SOURCE_DIR}/srt-live-server.cpp)
target_link_libraries(srt_server
    PRIVATE
        sls_core
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        httplib
        BS_thread_pool
        Threads::Threads
        srt
)

add_executable(srt_client ${CMAKE_CURRENT_SOURCE_DIR}/srt-live-client.cpp)
target_link_libraries(srt_client
    PRIVATE
        sls_core
        spdlog::spdlog
        nlohmann_json::nlohmann_json
        httplib
        BS_thread_pool
        Threads::Threads
        srt
)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sls.conf ${CMAKE_BINARY_DIR}/bin/sls.conf COPYONLY)
