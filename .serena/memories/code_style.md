# Code Style and Conventions

## Naming Conventions
- **Classes**: PascalCase with prefix, e.g., `CSLSManager`, `CSLSPublisher`
- **Methods**: snake_case, e.g., `start()`, `get_stat_info()`
- **Member variables**: snake_case with `m_` prefix, e.g., `m_servers`, `m_worker_threads`
- **Constants**: UPPER_CASE, e.g., `DEFAULT_GROUP`, `URL_MAX_LEN`
- **Types**: snake_case with `_t` suffix, e.g., `sls_conf_srt_t`

## File Organization
- Header files: `.hpp`
- Implementation files: `.cpp`
- Headers use `#pragma once` or include guards
- Related classes grouped in same files (e.g., `SLSPublisher.cpp`/`.hpp`)

## Code Patterns
- Use `spdlog` for all logging with format strings
- JSON using nlohmann/json library with `json` type alias
- HTTP endpoints defined in `srt-live-server.cpp` using httplib
- Configuration handled via `sls_conf_*` structures and macros
- Thread-safe operations using mutexes where needed

## Memory Management
- Manual memory management with new/delete
- Cleanup in destructors
- Use of vectors for dynamic collections

## Error Handling
- Return codes: `SLS_OK`, `SLS_ERROR`
- Logging at appropriate levels (trace, debug, info, warn, error, critical)
