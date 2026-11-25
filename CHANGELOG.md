# Changelog

## 2026-11-25

- Added `analysisd.rule_tree_memory_warning` (default `25%`) and `analysisd.rule_tree_memory_limit` (default `0`), new in Wazuh 4.14.10 (`src/analysisd/rules.c` `w_rule_tree_read_threshold`).
- New `size` parameter kind: bytes, `N` + K/M/G/B, `1%..100%`, `0`; text input in the UI, server validation, limit-above-warning check (error 5109) for same-unit values.
- Apply tab: grep hint for `Rule tree` / 7621 / 5108 / 5109 in `ossec.log`.
- README: 83 options, rule tree row in "Facts behind the hints".

## 2026-11-14

- README: link to wazuh5-tuner for Wazuh 5; license badge and section corrected to Apache-2.0 (matches LICENSE).
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
