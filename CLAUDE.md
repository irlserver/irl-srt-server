# CLAUDE.md

Orientation for agents and new contributors working on this fork of `srt-live-server`. Skim this top to bottom before opening a PR.

## Build

```bash
git submodule update --init
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

Binaries land in `build/bin/`: `srt_server` (the server) and `srt_client` (a TS file pusher / SRT recorder used for testing).

System prerequisites: a C++17 compiler (GCC or Clang), CMake 3.10 or newer, OpenSSL headers (`openssl-dev` or `libssl-dev`), zlib headers (`zlib-dev` or `zlib1g-dev`), and the IRL SRT fork (`https://github.com/irlserver/srt`, branch `belabox`) built and installed on the host. The `Dockerfile` shows the exact CI steps and pins the SRT fork by commit. SLS builds and runs on Linux and on macOS; Windows is not supported.

## Layout

```
src/
  core/               # sls_core static library; all reusable engine code lives here
  srt-live-server.cpp # thin entry point -> srt_server binary
  srt-live-client.cpp # thin entry point -> srt_client test tool
  sls.conf            # canonical example config (also copied to build/bin/ at build time)
tests/                # doctest suite, built when -DSLS_BUILD_TESTS=ON
lib/                  # git submodules: spdlog, json, cpp-httplib, thread-pool, CxxUrl
plans/                # improvement plans (advisor / executor workflow)
```

The two executables are thin (mostly argument parsing plus a call into the engine). All engine code lives behind `sls_core`. Anything reused between server and client, or anything that benefits from unit tests, belongs in `src/core/`.

## Where the live SRT socket boundary is

The live SRT socket boundary lives in `src/core/SLSSrt.cpp` (`CSLSSrt`) and its callers (`SLSListener*`, `SLSRole`, `SLSPublisher`, `SLSPlayer`, `SLSPuller`, `SLSPusher`). Calls to `srt_*` (`srt_accept`, `srt_recvmsg2`, `srt_sendmsg2`, `srt_setsockopt`, `srt_close`, etc.) belong on that side of the boundary.

Unit tests must stay off the live socket. The doctest harness exercises pure logic such as the sid parser (`sls_sid.cpp`), the auth reject cache (`auth_reject_cache.cpp`), bitrate limiting (`SLSBitrateLimit.cpp`), and the recycle array (`SLSArray.cpp`). When you need to unit test something that today reaches into a live socket, lift the testable logic into a helper and pass the SRT call result in as a value or a callback rather than building a fake `SRTSOCKET`.

## Tests

Unit tests are doctest based and run through CTest.

```bash
cmake -S . -B build -DSLS_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

To add a test:

1. Create `tests/test_<area>.cpp` and `#include "doctest.h"` followed by the headers you exercise.
2. Use `TEST_CASE("...")` / `SUBCASE("...")` from doctest; do not define `main` (that lives in `tests/test_main.cpp`).
3. Add the new file to `tests/CMakeLists.txt`.

## Sanitizers

This project carries manual memory ring buffers (`SLSRecycleArray`) and a fair amount of cross thread shared state across `SLSRole`, `SLSSrt`, the listener, and the manager. Run at least one sanitizer build before submitting a PR that touches any of those, or any code on the listener / manager threading boundary. The two flavors are mutually exclusive.

```bash
# ASan + UBSan
cmake -S . -B build-asan -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON -DSLS_SANITIZE=ON
cmake --build build-asan -j && ctest --test-dir build-asan --output-on-failure

# TSan
cmake -S . -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DSLS_BUILD_TESTS=ON -DSLS_TSAN=ON
cmake --build build-tsan -j && ctest --test-dir build-tsan --output-on-failure
```

CI runs all three matrix entries (Release, ASan + UBSan, TSan) on every push.

## Code style

`.clang-format` and `.clang-tidy` are checked into the root. Match the surrounding code; if you cannot tell what the conventions are in a file, run `clang-format -i <file>` against the configured style and stop there.

## Configuration and feature docs

- [`CONFIGURATION.md`](CONFIGURATION.md). Catalogue of every IRL specific config directive (and the base directives whose behavior changed in this fork).
- [`BITRATE_LIMITING.md`](BITRATE_LIMITING.md). Publisher bitrate ceiling with spike tolerance and sustained violation timeout.
- [`PLAYER_KEY_IMPLEMENTATION.md`](PLAYER_KEY_IMPLEMENTATION.md). Full player key auth protocol and response schema.
- [`README.md`](README.md). User facing setup and quickstart.
- [`ChangeLog.md`](ChangeLog.md). Fork history grouped by version.

## Commit conventions

- Conventional commits, lowercase, scoped to the package or area being changed. The scope is the affected unit (`core`, `sls`, `http`, `audio-gap`, `bitrate`, `conf`, `build`, `docker`, `deps`, `ci`, `docs`), not a file path or parent folder.
- Examples: `feat(sls): publisher takeover on reconnect`, `fix(core): null-check strdup(sid) on the accept path`, `chore(deps): pin cpp-httplib and json submodules to release tags`.
- Keep messages short. Explain the why in the body when it is not obvious.
- Never bypass hooks (`--no-verify`) unless explicitly asked. Never amend a commit that already shipped to a shared branch.

## Submodule pinning

Vendored libraries under `lib/` are pinned via git submodules. The IRL SRT fork is not a submodule; it is pinned by commit hash in the `ARG SRT_COMMIT=...` line of `Dockerfile`. See the "Bumping vendored submodules" section in `README.md` for the workflow.

## Plans and advisor workflow

The `plans/` directory holds incremental improvement plans driven by the advisor and executor agents. Each plan file is self contained. New work that does not have an associated plan is fine; if you are touching a system that has a plan, read the plan first so you do not undo or duplicate landed work.
