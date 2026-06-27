add_library(doctest INTERFACE)
target_include_directories(doctest INTERFACE ${PROJECT_SOURCE_DIR}/lib/doctest)

add_executable(sls_tests
    test_main.cpp
    test_sls_sid.cpp
    test_recycle_array.cpp
    test_auth_reject_cache.cpp
    test_bitrate_limit.cpp
    test_audio_gap_filler.cpp
    test_idle.cpp
    test_push_url.cpp
    test_ip_acl.cpp
    test_ts_parser.cpp
    test_map_data.cpp
)
target_link_libraries(sls_tests PRIVATE sls_core doctest srt)
add_test(NAME unit COMMAND sls_tests)
