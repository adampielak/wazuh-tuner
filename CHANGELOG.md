# Changelog

## 2026-11-14

- Rewrite: one file, Python standard library only, Flask dependency removed.
- Parameter table checked against Wazuh 4.14.10 source: 81 options, defaults and ranges.
- Fixed wrong names and ranges (`remoted.control_msg_queue_size`, `wazuh_modules.task_nice` 0..19, `wazuh_modules.rlimit_nofile` min 8192, `syscheck.rt_delay`, `logcollector.max_lines`).
- Added missing analysisd thread pools and queues, `wazuh_db` options, `monitord`, `wazuh.thread_stack_size`.
- Server-side validation in `POST /api/generate`: unknown key, non-integer, out of range, newline injection rejected with HTTP 400.
- Generated file contains changed options only by default.
- Presets: burst buffers, many agents per node, shared host, debug.
- Apply and verify tab with commands matched to changed options.
- `--check` compares built-in defaults with a node's `internal_options.conf`.
- `--host` defaults to 127.0.0.1.
- Startup no longer waits on reverse DNS (`socket.getfqdn`).
- Unit and HTTP tests in `tests/`.
- New screenshots, README rewritten.
