# libFuzzer harnesses for the three network-boundary input parsers. Reached only
# via the top-level, clang-only SLS_FUZZ option, which already instruments
# sls_core (and the whole tree) with -fsanitize=fuzzer-no-link,address,undefined.
# Each target here additionally links -fsanitize=fuzzer, which supplies the
# libFuzzer driver and main(); sls_core has no main of its own so there is no
# clash.
#
# The targets link the REAL sls_core — the same object code that ships — so the
# fuzzed parser is byte-for-byte the production one. The harnesses add NO parsing
# or validation logic; they only drive the existing entry points. `srt` is linked
# explicitly (mirroring tests/CMakeLists.txt) because sls_sid.o references libsrt
# symbols even though the fuzzed streamid functions themselves do not.

set(SLS_FUZZ_TARGETS
    fuzz_ts_parser
    fuzz_streamid
    fuzz_conf
)

foreach(tgt ${SLS_FUZZ_TARGETS})
    add_executable(${tgt} ${tgt}.cpp)
    target_compile_options(${tgt} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_options(${tgt} PRIVATE -fsanitize=fuzzer,address,undefined)
    target_link_libraries(${tgt} PRIVATE sls_core srt)
endforeach()
