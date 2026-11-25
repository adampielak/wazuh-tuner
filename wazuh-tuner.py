#!/usr/bin/env python3
"""Wazuh manager local_internal_options.conf tuning UI.

Parameter names, defaults and ranges match the getDefine_Int() calls in the
Wazuh v4.14.10 source; the two rule_tree_memory_* options use getDefine_String()
with a size or percent format. A value outside the range, or one that is not a plain
non-negative integer, makes the daemon exit at start.

Run:   python3 wazuh-tuner.py [--host 127.0.0.1] [--port 7437]
Check: python3 wazuh-tuner.py --check /var/ossec/etc/internal_options.conf
"""
import argparse
import json
import re
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WAZUH_VERSION = "4.14.10"


def p(key, default, lo, hi, desc):
    return {"key": key, "default": default, "min": lo, "max": hi, "desc": desc}


def size_p(key, default, desc):
    # Text option parsed by w_rule_tree_read_threshold(): bytes, N[KMGB], N% (1..100) or 0.
    return {"key": key, "default": default, "kind": "size", "desc": desc}


# w_parse_size() suffixes, case-insensitive. 4.14.10 sscanf ignores trailing junk; this is stricter.
SIZE_RE = re.compile(r"(\d+)([KkMmGgBb]?)")
SIZE_MULT = {"": 1, "b": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}


def parse_size(raw):
    """Return ('pct', n), ('bytes', n) or None when analysisd would exit with INV_DEF."""
    s = str(raw).strip()
    m = re.fullmatch(r"(\d+)%", s)
    if m:
        n = int(m.group(1))
        return ("pct", n) if 1 <= n <= 100 else None
    m = SIZE_RE.fullmatch(s)
    if not m:
        return None
    return ("bytes", int(m.group(1)) * SIZE_MULT[m.group(2).lower()])


QUEUE_MAX = 2000000

PARAMS = {
    "analysisd": {
        "label": "Analysis Daemon (wazuh-analysisd)",
        "desc": "Decoding and rule matching. Thread count 0 means one thread per CPU core for that pool. "
                "Watch /var/ossec/var/run/wazuh-analysisd.state: a growing *_dropped counter names the queue to raise.",
        "params": [
            p("analysisd.event_threads", 0, 0, 32, "Decoder threads for log events (0 = CPU cores)."),
            p("analysisd.syscheck_threads", 0, 0, 32, "Decoder threads for FIM events (0 = CPU cores)."),
            p("analysisd.syscollector_threads", 0, 0, 32, "Decoder threads for syscollector events (0 = CPU cores)."),
            p("analysisd.rootcheck_threads", 0, 0, 32, "Decoder threads for rootcheck events (0 = CPU cores)."),
            p("analysisd.sca_threads", 0, 0, 32, "Decoder threads for SCA events (0 = CPU cores)."),
            p("analysisd.hostinfo_threads", 0, 0, 32, "Decoder threads for hostinfo events (0 = CPU cores)."),
            p("analysisd.winevt_threads", 0, 0, 32, "Decoder threads for Windows eventchannel events (0 = CPU cores)."),
            p("analysisd.rule_matching_threads", 0, 0, 32, "Rule matching threads (0 = CPU cores)."),
            p("analysisd.dbsync_threads", 0, 0, 32, "Database synchronization dispatcher threads (0 = CPU cores)."),
            p("analysisd.decode_event_queue_size", 16384, 128, QUEUE_MAX,
              "Input queue for log events. Raise when events_dropped grows during bursts."),
            p("analysisd.decode_syscheck_queue_size", 16384, 128, QUEUE_MAX, "Input queue for FIM events."),
            p("analysisd.decode_syscollector_queue_size", 16384, 128, QUEUE_MAX, "Input queue for syscollector events."),
            p("analysisd.decode_rootcheck_queue_size", 16384, 128, QUEUE_MAX,
              "Input queue for rootcheck events. Agents started together run rootcheck in the same minute "
              "(default frequency 12 h) and can overflow it."),
            p("analysisd.decode_sca_queue_size", 16384, 128, QUEUE_MAX, "Input queue for SCA events."),
            p("analysisd.decode_hostinfo_queue_size", 16384, 128, QUEUE_MAX, "Input queue for hostinfo events."),
            p("analysisd.decode_winevt_queue_size", 16384, 128, QUEUE_MAX, "Input queue for Windows eventchannel events."),
            p("analysisd.dbsync_queue_size", 16384, 128, QUEUE_MAX, "Input queue for database synchronization messages."),
            p("analysisd.decode_output_queue_size", 16384, 128, QUEUE_MAX, "Queue between decoders and rule matching."),
            p("analysisd.alerts_queue_size", 16384, 128, QUEUE_MAX, "Writer queue for alerts.log / alerts.json."),
            p("analysisd.archives_queue_size", 16384, 128, QUEUE_MAX,
              "Writer queue for archives. Only used when logall or logall_json is on."),
            p("analysisd.rlimit_nofile", 458752, 1024, 1048576,
              "Open file limit. The daemon calls setrlimit() as root before it drops privileges."),
            p("analysisd.default_timeframe", 360, 60, 3600, "Default rule timeframe in seconds."),
            p("analysisd.decoder_order_size", 256, 32, 1024, "Maximum fields in a decoder <order> tag."),
            p("analysisd.min_rotate_interval", 600, 10, 86400, "Minimum seconds between output file rotations."),
            p("analysisd.state_interval", 5, 0, 86400, "Seconds between wazuh-analysisd.state updates (0 = off)."),
            p("analysisd.debug", 0, 0, 2, "Debug level. 2 floods ossec.log; do not keep it in production."),
            size_p("analysisd.rule_tree_memory_warning", "25%",
                   "New in 4.14.10. Rule tree size that logs warning 7621 while loading rules. Bytes, N K/M/G, "
                   "or 1%..100% of physical RAM (cgroup limit in a container); 0 = off. Converted to nodes "
                   "(32 B each on 64-bit); the start log shows the result as INFO 'Rule tree threshold'."),
            size_p("analysisd.rule_tree_memory_limit", "0",
                   "New in 4.14.10. Rule tree size that stops loading: error 5108 names the rule that crossed it. "
                   "Same format; 0 = off (default). Must exceed the warning, else error 5109 and analysisd exits."),
        ],
    },
    "remoted": {
        "label": "Remote Daemon (wazuh-remoted)",
        "desc": "Agent connections. Watch /var/ossec/var/run/wazuh-remoted.state for discarded messages and queue_size.",
        "params": [
            p("remoted.worker_pool", 4, 1, 16, "Threads that process received agent messages."),
            p("remoted.sender_pool", 8, 1, 64, "Threads that send shared files to agents."),
            p("remoted.request_pool", 1024, 1, 4096, "Limit of parallel request dispatchers."),
            p("remoted.send_buffer_size", 131072, 65536, 1048576,
              "Per-agent outgoing queue in bytes, kept in user space. It is not a socket buffer."),
            p("remoted.control_msg_queue_size", 16384, 4096, 1048576, "Queue for agent control (keepalive) messages."),
            p("remoted.rlimit_nofile", 458752, 1024, 1048576,
              "Open file limit. Each TCP agent holds one descriptor."),
            p("remoted.receive_chunk", 4096, 1024, 16384, "TCP read size in bytes. Use a power of two."),
            p("remoted.send_chunk", 4096, 512, 16384, "TCP write size in bytes. Use a power of two."),
            p("remoted.tcp_keepidle", 30, 1, 7200, "Idle seconds before keepalive probes. Set per socket, kernel sysctl not used."),
            p("remoted.tcp_keepintvl", 10, 1, 100, "Seconds between keepalive probes."),
            p("remoted.tcp_keepcnt", 3, 1, 50, "Failed probes before the connection is dropped."),
            p("remoted.keyupdate_interval", 10, 1, 3600, "Seconds between client.keys reload checks."),
            p("remoted.shared_reload", 10, 1, 18000, "Seconds between shared file (agent groups) reloads."),
            p("remoted.state_interval", 5, 0, 86400, "Seconds between wazuh-remoted.state updates (0 = off)."),
            p("remoted.debug", 0, 0, 2, "Debug level."),
        ],
    },
    "wazuh_db": {
        "label": "Wazuh DB (wazuh-db)",
        "desc": "Per-agent SQLite databases. Slow storage shows here first; tuning only hides it.",
        "params": [
            p("wazuh_db.worker_pool_size", 8, 1, 32, "Worker threads."),
            p("wazuh_db.open_db_limit", 64, 1, 4096,
              "Databases kept open. Above the limit the least recently used one is closed."),
            p("wazuh_db.commit_time_min", 10, 1, 3600, "Minimum seconds before a commit."),
            p("wazuh_db.commit_time_max", 60, 1, 3600, "Maximum seconds before a forced commit."),
            p("wazuh_db.rlimit_nofile", 458752, 1024, 1048576, "Open file limit."),
            p("wazuh_db.max_fragmentation", 90, 0, 100, "Fragmentation percent that always triggers VACUUM."),
            p("wazuh_db.fragmentation_threshold", 75, 0, 100, "Fragmentation percent that allows VACUUM."),
            p("wazuh_db.fragmentation_delta", 5, 0, 100,
              "Fragmentation growth since the last VACUUM needed for a new one."),
            p("wazuh_db.free_pages_percentage", 0, 0, 99, "Minimum free pages percent that can trigger VACUUM."),
            p("wazuh_db.check_fragmentation_interval", 7200, 1, 30758400, "Seconds between fragmentation checks."),
            p("wazuh_db.debug", 0, 0, 2, "Debug level."),
        ],
    },
    "logcollector": {
        "label": "Log Collector (wazuh-logcollector)",
        "desc": "The manager's own log collection (localfile in the manager ossec.conf). Agents read their own file.",
        "params": [
            p("logcollector.input_threads", 4, 1, 128, "File reader threads."),
            p("logcollector.queue_size", 1024, 128, 220000, "Output queue. Raise when the state file shows drops."),
            p("logcollector.max_lines", 10000, 0, 1000000,
              "Lines read from one file per loop (0 = no limit)."),
            p("logcollector.max_files", 1000, 1, 100000, "Maximum monitored files."),
            p("logcollector.rlimit_nofile", 1100, 1024, 1048576, "Open file limit. Must be higher than max_files."),
            p("logcollector.loop_timeout", 2, 1, 120, "Seconds between file change checks."),
            p("logcollector.vcheck_files", 64, 0, 1024, "Seconds between file existence and rotation checks."),
            p("logcollector.sock_fail_time", 300, 1, 3600, "Seconds before a failed output socket is retried."),
            p("logcollector.state_interval", 60, 0, 3600, "Seconds between state file updates (0 = off)."),
            p("logcollector.debug", 0, 0, 2, "Debug level."),
        ],
    },
    "syscheck": {
        "label": "FIM (wazuh-syscheckd)",
        "desc": "The manager's own file integrity monitoring.",
        "params": [
            p("syscheck.rt_delay", 5, 0, 1000, "Milliseconds of delay for real-time events (skips editor temp files)."),
            p("syscheck.max_audit_entries", 256, 1, 4096, "Maximum directories monitored in whodata mode on Linux."),
            p("syscheck.default_max_depth", 256, 1, 320, "Maximum recursion depth."),
            p("syscheck.symlink_scan_interval", 600, 1, 2592000, "Seconds between checks of configured symbolic links."),
            p("syscheck.file_max_size", 1024, 0, 4095, "Largest file hashed, in MiB (0 = no limit)."),
            p("syscheck.debug", 0, 0, 2, "Debug level."),
        ],
    },
    "wazuh_modules": {
        "label": "Modules (wazuh-modulesd)",
        "desc": "Vulnerability detection, syscollector, SCA and other modules.",
        "params": [
            p("wazuh_modules.max_eps", 100, 1, 1000, "Events per second sent by each module."),
            # The parser accepts digits only, so a negative nice value stops the daemon.
            p("wazuh_modules.task_nice", 10, 0, 19,
              "Nice value for module tasks. Negative values stop wazuh-modulesd at start in 4.14 "
              "(the parser rejects '-'), so the range here starts at 0."),
            p("wazuh_modules.kill_timeout", 10, 0, 3600, "Seconds before a module child process is killed (0 = at once)."),
            p("wazuh_modules.rlimit_nofile", 8192, 8192, 1048576, "Open file limit. Values under 8192 are rejected."),
            p("wazuh_modules.debug", 0, 0, 2, "Debug level."),
        ],
    },
    "monitord": {
        "label": "Monitor Daemon (wazuh-monitord)",
        "desc": "Rotation of ossec.log and agent disconnection checks.",
        "params": [
            p("monitord.rotate_log", 1, 0, 1, "Rotate internal logs daily."),
            p("monitord.compress", 1, 0, 1, "Compress rotated logs."),
            p("monitord.keep_log_days", 31, 0, 500, "Days of rotated internal logs to keep."),
            p("monitord.size_rotate", 512, 0, 4096, "Size in MiB that triggers rotation (0 = off)."),
            p("monitord.daily_rotations", 12, 1, 256, "Maximum rotations per day."),
            p("monitord.day_wait", 10, 0, 600, "Seconds to wait before rotating, compressing and signing."),
            p("monitord.debug", 0, 0, 2, "Debug level."),
        ],
    },
    "wazuh": {
        "label": "Global (wazuh)",
        "desc": "Settings shared by all daemons.",
        "params": [
            p("wazuh.thread_stack_size", 8192, 2048, 65536,
              "Thread stack in KiB, set with pthread_attr_setstacksize(). Memory use grows with "
              "threads x stack. No ulimit or systemd change is needed."),
        ],
    },
}

ALL_PARAMS = {x["key"]: x for s in PARAMS.values() for x in s["params"]}

PRESETS = {
    "default": {
        "label": "Default",
        "desc": "Vendor defaults. Use it to reset.",
        "values": {},
    },
    "burst": {
        "label": "Burst buffers",
        "desc": "Larger analysisd input and output queues. For drops during restarts or scan bursts. "
                "Costs memory only while the queues fill.",
        "values": {
            "analysisd.decode_event_queue_size": 131072,
            "analysisd.decode_syscheck_queue_size": 65536,
            "analysisd.decode_syscollector_queue_size": 65536,
            "analysisd.decode_rootcheck_queue_size": 65536,
            "analysisd.decode_sca_queue_size": 65536,
            "analysisd.decode_winevt_queue_size": 131072,
            "analysisd.decode_output_queue_size": 131072,
            "analysisd.alerts_queue_size": 131072,
            "analysisd.archives_queue_size": 131072,
        },
    },
    "many_agents": {
        "label": "Many agents per node",
        "desc": "More than about 1000 agents on one node: more remoted and wazuh-db workers, "
                "larger control queue, more open agent databases.",
        "values": {
            "remoted.worker_pool": 8,
            "remoted.sender_pool": 16,
            "remoted.control_msg_queue_size": 65536,
            "wazuh_db.worker_pool_size": 16,
            "wazuh_db.open_db_limit": 1024,
        },
    },
    "shared_host": {
        "label": "Shared host",
        "desc": "Manager next to other services. Caps analysisd pools at 4 threads each "
                "instead of one per core.",
        "values": {
            "analysisd.event_threads": 4,
            "analysisd.syscheck_threads": 2,
            "analysisd.syscollector_threads": 2,
            "analysisd.rootcheck_threads": 1,
            "analysisd.sca_threads": 1,
            "analysisd.hostinfo_threads": 1,
            "analysisd.winevt_threads": 2,
            "analysisd.rule_matching_threads": 4,
            "analysisd.dbsync_threads": 2,
        },
    },
    "debug": {
        "label": "Debug (temporary)",
        "desc": "debug=1 on every daemon. Revert after the test.",
        "values": {k: 1 for k in ALL_PARAMS if k.endswith(".debug")},
    },
}


def validate(values):
    """Return (clean, errors). Only known keys with in-range integers pass."""
    clean, errors = {}, []
    for key, raw in values.items():
        spec = ALL_PARAMS.get(key)
        if spec is None:
            errors.append(f"{key}: unknown parameter")
            continue
        if spec.get("kind") == "size":
            if isinstance(raw, bool) or parse_size(raw) is None:
                errors.append(f"{key}: '{raw}' is not a size (bytes, N K/M/G, 1%..100%, 0)")
                continue
            clean[key] = str(raw).strip()
            continue
        if isinstance(raw, bool) or not re.fullmatch(r"\d+", str(raw).strip()):
            errors.append(f"{key}: '{raw}' is not a non-negative integer")
            continue
        v = int(str(raw).strip())
        if not spec["min"] <= v <= spec["max"]:
            errors.append(f"{key}: {v} outside [{spec['min']}..{spec['max']}]")
            continue
        clean[key] = v
    w = parse_size(clean.get("analysisd.rule_tree_memory_warning", "25%"))
    lim = parse_size(clean.get("analysisd.rule_tree_memory_limit", "0"))
    # Same unit only: mixing % and bytes depends on the node's RAM (checked by analysisd, error 5109).
    if w and lim and w[1] and lim[1] and w[0] == lim[0] and w[1] >= lim[1]:
        errors.append("analysisd.rule_tree_memory_limit must exceed rule_tree_memory_warning (error 5109)")
    return clean, errors


def generate(values, changed_only=True):
    lines = ["# /var/ossec/etc/local_internal_options.conf",
             f"# Checked against Wazuh {WAZUH_VERSION} internal_options.conf ranges.", ""]
    for section in PARAMS.values():
        rows = []
        for spec in section["params"]:
            v = values.get(spec["key"], spec["default"])
            if changed_only and v == spec["default"]:
                continue
            rows.append(f"{spec['key']}={v}")
        if rows:
            lines.append(f"# {section['label']}")
            lines += rows + [""]
    return "\n".join(lines)


def check_defaults(path):
    """Compare PARAMS defaults with an installed internal_options.conf."""
    found = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = re.match(r"\s*([\w.-]+)=(\S*)", line)
            if m:
                found[m.group(1)] = m.group(2)
    rc = 0
    for key, spec in ALL_PARAMS.items():
        if key not in found:
            print(f"MISSING  {key} (not in {path})")
            rc = 1
        elif found[key] != str(spec["default"]):
            print(f"DEFAULT  {key}: tuner {spec['default']}, file {found[key]}")
            rc = 1
    if rc == 0:
        print(f"OK: {len(ALL_PARAMS)} parameters match {path}")
    return rc


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wazuh Tuner</title>
<style>
:root {
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --warn:#d29922;--danger:#f85149;--ok:#3fb950;--code-bg:#010409;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;}
.layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh;}
.sidebar{background:var(--surface);border-right:1px solid var(--border);padding:16px;position:sticky;top:0;height:100vh;overflow-y:auto;}
.sidebar h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;}
.nav-item{display:block;padding:8px 10px;border-radius:6px;color:var(--muted);font-size:13px;cursor:pointer;margin-bottom:2px;border:none;background:none;width:100%;text-align:left;}
.nav-item:hover,.nav-item.active{background:rgba(88,166,255,.15);color:var(--accent);}
.nav-count{float:right;font-size:11px;color:var(--accent);}
.preset-btn{display:block;width:100%;text-align:left;padding:8px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:12px;cursor:pointer;margin-bottom:4px;}
.preset-btn:hover{border-color:var(--accent);color:var(--accent);}
.preset-note{font-size:11px;color:var(--muted);margin-top:6px;line-height:1.4;}
.main{padding:24px 32px;max-width:1100px;}
.section{display:none;}
.section.active{display:block;}
.section-header{margin-bottom:20px;}
.section-header h1{font-size:20px;font-weight:600;margin-bottom:4px;}
.section-header p{color:var(--muted);font-size:13px;line-height:1.5;}
.param-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;}
.param-card.changed{border-color:var(--accent);}
.param-key{font-family:ui-monospace,monospace;font-size:13px;color:var(--accent);margin-bottom:4px;}
.param-badge{display:inline-block;font-size:11px;padding:2px 6px;border-radius:10px;background:rgba(88,166,255,.15);color:var(--accent);margin-left:6px;}
.param-desc{font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.5;}
.input-row{display:flex;align-items:center;gap:12px;}
.input-row input[type=range]{flex:1;accent-color:var(--accent);}
.input-row input[type=number]{width:120px;background:var(--code-bg);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-size:13px;}
.range-bounds{font-size:11px;color:var(--muted);white-space:nowrap;}
.radio-row{display:flex;gap:16px;}
.radio-row label{display:flex;align-items:center;gap:4px;cursor:pointer;font-size:13px;}
.output-section{background:var(--code-bg);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:16px;}
.output-section pre{color:var(--ok);font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;}
.btn{padding:8px 16px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500;}
.btn-primary{background:var(--accent);color:#000;}
.btn-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border);}
.btn-danger{background:rgba(248,81,73,.15);color:var(--danger);border:1px solid var(--danger);}
.toolbar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap;align-items:center;}
.tab-bar{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);}
.tab{padding:8px 16px;cursor:pointer;color:var(--muted);font-size:13px;border-bottom:2px solid transparent;margin-bottom:-1px;}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.tab-content{display:none;}
.tab-content.active{display:block;}
.warn-box{background:rgba(210,153,34,.1);border:1px solid var(--warn);border-radius:6px;padding:12px 16px;margin-bottom:8px;font-size:12px;color:var(--warn);white-space:pre-line;line-height:1.5;}
.info-box{background:rgba(88,166,255,.1);border:1px solid var(--accent);border-radius:6px;padding:12px 16px;margin-bottom:8px;font-size:12px;color:var(--accent);white-space:pre-line;line-height:1.5;}
@media (max-width:760px){.layout{grid-template-columns:1fr;}.sidebar{position:static;height:auto;}.main{padding:16px;}}
</style>
</head>
<body>
<div class="layout">
  <div class="sidebar">
    <h2>Sections</h2>
    <div id="nav"></div>
    <div style="margin-top:24px">
      <h2 style="margin-bottom:8px">Presets</h2>
      <div id="presets"></div>
      <div class="preset-note">A preset replaces all current values. Presets are starting points, not sizing rules: change one thing, measure the .state files, repeat.</div>
    </div>
  </div>
  <div class="main" id="main"></div>
</div>
<script>
const PARAMS = __PARAMS__;
const PRESETS = __PRESETS__;
const WAZUH_VERSION = __VERSION__;
const SECTION_KEYS = Object.keys(PARAMS);
const ALL = Object.fromEntries(Object.values(PARAMS).flatMap(s => s.params).map(p => [p.key, p]));
let values = {};

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function getValue(key) {
  return values[key] !== undefined ? values[key] : ALL[key].default;
}

function changedIn(sid) {
  return PARAMS[sid].params.filter(p => getValue(p.key) !== p.default).length;
}

function refreshNav() {
  document.querySelectorAll('.nav-item').forEach(b => {
    const c = b.querySelector('.nav-count');
    if (!c) return;
    const n = changedIn(b.dataset.section);
    c.textContent = n ? String(n) : '';
  });
}

function buildNav() {
  const nav = document.getElementById('nav');
  const items = SECTION_KEYS.map(k => [k, PARAMS[k].label.split(' (')[0]])
    .concat([['output', 'Generate config'], ['system', 'Apply and verify']]);
  items.forEach(([id, label], i) => {
    const btn = el('button', 'nav-item' + (i === 0 ? ' active' : ''), label);
    btn.dataset.section = id;
    if (PARAMS[id]) btn.appendChild(el('span', 'nav-count'));
    btn.addEventListener('click', () => showSection(id));
    nav.appendChild(btn);
  });
}

function buildPresets() {
  const cont = document.getElementById('presets');
  Object.entries(PRESETS).forEach(([id, preset]) => {
    const btn = el('button', 'preset-btn', preset.label);
    btn.title = preset.desc;
    btn.addEventListener('click', () => applyPreset(id));
    cont.appendChild(btn);
  });
}

function buildParamCard(p) {
  const card = el('div', 'param-card');
  card.id = 'card-' + p.key;
  const keyLine = el('div', 'param-key', p.key);
  keyLine.appendChild(el('span', 'param-badge', 'default ' + p.default +
    (p.kind === 'size' ? ', bytes, K/M/G or 1%..100%' : ', range ' + p.min + '..' + p.max)));
  card.appendChild(keyLine);
  card.appendChild(el('div', 'param-desc', p.desc));

  const val = getValue(p.key);
  if (p.kind === 'size') {
    const row = el('div', 'input-row');
    const txt = document.createElement('input');
    txt.type = 'text';
    txt.id = 'num-' + p.key;
    txt.value = val;
    // Revert invalid input: analysisd exits on a value it cannot parse.
    txt.addEventListener('change', () => {
      let v = txt.value.trim();
      const m = /^(\\d+)%$/.exec(v);
      if (!(m ? +m[1] >= 1 && +m[1] <= 100 : /^\\d+[KkMmGgBb]?$/.test(v))) v = p.default;
      txt.value = v; setVal(p.key, v);
    });
    row.appendChild(txt);
    card.appendChild(row);
  } else if (p.min === 0 && (p.max === 1 || p.max === 2)) {
    const row = el('div', 'radio-row');
    for (let o = 0; o <= p.max; o++) {
      const lbl = el('label');
      const inp = document.createElement('input');
      inp.type = 'radio';
      inp.name = p.key;
      inp.value = o;
      inp.checked = val === o;
      inp.addEventListener('change', () => setVal(p.key, o));
      lbl.appendChild(inp);
      lbl.appendChild(document.createTextNode(' ' + o));
      row.appendChild(lbl);
    }
    card.appendChild(row);
  } else {
    const row = el('div', 'input-row');
    const range = document.createElement('input');
    range.type = 'range';
    range.id = 'range-' + p.key;
    range.min = p.min; range.max = p.max; range.value = val;
    const num = document.createElement('input');
    num.type = 'number';
    num.id = 'num-' + p.key;
    num.min = p.min; num.max = p.max; num.step = 1; num.value = val;
    range.addEventListener('input', () => { num.value = range.value; setVal(p.key, parseInt(range.value, 10)); });
    // Clamp on blur: an out-of-range value would stop the daemon.
    num.addEventListener('change', () => {
      let v = parseInt(num.value, 10);
      if (isNaN(v)) v = p.default;
      v = Math.min(p.max, Math.max(p.min, v));
      num.value = v; range.value = v; setVal(p.key, v);
    });
    row.appendChild(el('span', 'range-bounds', String(p.min)));
    row.appendChild(range);
    row.appendChild(num);
    row.appendChild(el('span', 'range-bounds', String(p.max)));
    card.appendChild(row);
  }
  if (val !== p.default) card.classList.add('changed');
  return card;
}

function buildSection(sid) {
  const s = PARAMS[sid];
  const div = el('div', 'section');
  div.id = 'section-' + sid;
  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, s.label));
  hdr.appendChild(el('p', null, s.desc));
  div.appendChild(hdr);
  s.params.forEach(p => div.appendChild(buildParamCard(p)));
  return div;
}

function buildOutputSection() {
  const div = el('div', 'section');
  div.id = 'section-output';
  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, 'Generate config'));
  hdr.appendChild(el('p', null, 'Deploy the changed-only file. A file that repeats every default pins today\\'s values and hides default changes in later Wazuh releases.'));
  div.appendChild(hdr);

  const toolbar = el('div', 'toolbar');
  const copyBtn = el('button', 'btn btn-primary', 'Copy');
  copyBtn.id = 'copy-btn';
  copyBtn.addEventListener('click', copyConf);
  const dlBtn = el('button', 'btn btn-secondary', 'Download');
  dlBtn.addEventListener('click', downloadConf);
  const resetBtn = el('button', 'btn btn-danger', 'Reset to defaults');
  resetBtn.addEventListener('click', () => applyPreset('default'));
  [copyBtn, dlBtn, resetBtn].forEach(b => toolbar.appendChild(b));
  div.appendChild(toolbar);

  const tabBar = el('div', 'tab-bar');
  [['diff', 'Changed only'], ['conf', 'All parameters (reference)']].forEach(([t, label], i) => {
    const tab = el('div', 'tab' + (i === 0 ? ' active' : ''), label);
    tab.dataset.tab = t;
    tab.addEventListener('click', () => switchTab(t));
    tabBar.appendChild(tab);
  });
  div.appendChild(tabBar);
  ['diff', 'conf'].forEach((t, i) => {
    const tc = el('div', 'tab-content' + (i === 0 ? ' active' : ''));
    tc.id = 'tab-' + t;
    const out = el('div', 'output-section');
    const pre = el('pre');
    pre.id = 'out-' + t;
    out.appendChild(pre);
    tc.appendChild(out);
    div.appendChild(tc);
  });
  return div;
}

function buildSystemSection() {
  const div = el('div', 'section');
  div.id = 'section-system';
  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, 'Apply and verify'));
  hdr.appendChild(el('p', null, 'Steps and OS checks for the current values.'));
  div.appendChild(hdr);
  const content = el('div');
  content.id = 'sys-content';
  div.appendChild(content);
  return div;
}

function buildMain() {
  const main = document.getElementById('main');
  SECTION_KEYS.forEach(id => main.appendChild(buildSection(id)));
  main.appendChild(buildOutputSection());
  main.appendChild(buildSystemSection());
  document.getElementById('section-' + SECTION_KEYS[0]).classList.add('active');
}

function showSection(id) {
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.section === id));
  document.getElementById('section-' + id).classList.add('active');
  if (id === 'output') updateOutput();
  if (id === 'system') updateSystemHints();
}

function setVal(key, val) {
  values[key] = val;
  const card = document.getElementById('card-' + key);
  if (card) card.classList.toggle('changed', val !== ALL[key].default);
  refreshNav();
}

function generateConf(changedOnly) {
  const lines = ['# /var/ossec/etc/local_internal_options.conf',
                 '# Checked against Wazuh ' + WAZUH_VERSION + ' internal_options.conf ranges.', ''];
  let n = 0;
  Object.values(PARAMS).forEach(section => {
    const ps = section.params.filter(p => !changedOnly || getValue(p.key) !== p.default);
    if (!ps.length) return;
    lines.push('# ' + section.label);
    ps.forEach(p => { lines.push(p.key + '=' + getValue(p.key)); n++; });
    lines.push('');
  });
  if (changedOnly && n === 0) return '# No parameter differs from the defaults.';
  return lines.join('\\n');
}

function updateOutput() {
  document.getElementById('out-conf').textContent = generateConf(false);
  document.getElementById('out-diff').textContent = generateConf(true);
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === tab));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.toggle('active', t.id === 'tab-' + tab));
}

function copyConf() {
  navigator.clipboard.writeText(generateConf(true)).then(() => {
    const btn = document.getElementById('copy-btn');
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}

function downloadConf() {
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(generateConf(true) + '\\n');
  a.download = 'local_internal_options.conf';
  a.click();
}

function applyPreset(id) {
  values = { ...PRESETS[id].values };
  Object.values(ALL).forEach(p => {
    const v = getValue(p.key);
    const range = document.getElementById('range-' + p.key);
    const num = document.getElementById('num-' + p.key);
    if (range) range.value = v;
    if (num) num.value = v;
    document.querySelectorAll('input[name="' + p.key + '"]').forEach(r => { r.checked = parseInt(r.value, 10) === v; });
    const card = document.getElementById('card-' + p.key);
    if (card) card.classList.toggle('changed', v !== p.default);
  });
  refreshNav();
  updateOutput();
  updateSystemHints();
}

function addBlock(parent, cls, label, code) {
  parent.appendChild(el('div', cls, label));
  if (!code) return;
  const out = el('div', 'output-section');
  out.appendChild(el('pre', null, code));
  parent.appendChild(out);
}

function updateSystemHints() {
  const cont = document.getElementById('sys-content');
  while (cont.firstChild) cont.removeChild(cont.firstChild);
  const changed = Object.values(ALL).filter(p => getValue(p.key) !== p.default);

  addBlock(cont, 'info-box',
    '1. Write the changed-only file on every manager node that needs it. The cluster syncs client.keys from etc/, not this file.',
    'install -o root -g wazuh -m 640 local_internal_options.conf /var/ossec/etc/local_internal_options.conf');
  addBlock(cont, 'info-box',
    '2. Restart and confirm no daemon exited. Out-of-range or non-numeric values stop the daemon at start.',
    'systemctl restart wazuh-manager\\n/var/ossec/bin/wazuh-control status\\n' +
    'grep -iE "invalid definition|could not set resource limit|cannot set stack" /var/ossec/logs/ossec.log | tail');

  const fdKeys = Object.keys(ALL).filter(k => k.endsWith('.rlimit_nofile'));
  if (changed.some(p => fdKeys.includes(p.key))) {
    const procs = {analysisd: 'wazuh-analysisd', remoted: 'wazuh-remoted', wazuh_db: 'wazuh-db',
                   logcollector: 'wazuh-logcollector', wazuh_modules: 'wazuh-modulesd'};
    const cmds = fdKeys.map(k => {
      const d = k.split('.')[0];
      return 'grep "Max open files" /proc/$(pgrep -xo ' + procs[d] + ')/limits   # expect ' + getValue(k);
    });
    addBlock(cont, 'info-box',
      'Open file limits: each daemon calls setrlimit() as root before it drops privileges, so the unit\\'s LimitNOFILE=65536 ' +
      'and /etc/security/limits.conf do not cap it. The ceiling is fs.nr_open (kernel default 1048576). ' +
      'fs.file-max is system-wide: check it, never lower it.',
      cmds.join('\\n') + '\\nsysctl fs.nr_open fs.file-max\\ncat /proc/sys/fs/file-nr   # allocated, unused, max');
  }

  const queueBytes = changed.filter(p => p.key.endsWith('_queue_size') && p.key.startsWith('analysisd.'));
  if (queueBytes.length) {
    addBlock(cont, 'info-box',
      'Queues: each analysisd queue allocates size x 8 bytes of pointers at start; events use memory only while queued. ' +
      'Check the matching counters after a burst:',
      'grep -E "dropped|queue_usage|queue_size" /var/ossec/var/run/wazuh-analysisd.state');
  }

  if (changed.some(p => p.key.startsWith('analysisd.') && p.key.endsWith('_threads'))) {
    addBlock(cont, 'info-box', 'Threads: compare with the CPU count. 0 already means one thread per core for that pool.',
      'nproc\\nps -o nlwp= -p $(pgrep -xo wazuh-analysisd)');
  }

  if (getValue('wazuh.thread_stack_size') > ALL['wazuh.thread_stack_size'].default) {
    addBlock(cont, 'warn-box',
      'thread_stack_size: virtual memory grows by (new - 8192) KiB for each thread in every daemon. ' +
      'Raise it only after a stack overflow crash.', '');
  }

  if (getValue('syscheck.max_audit_entries') !== ALL['syscheck.max_audit_entries'].default) {
    addBlock(cont, 'info-box',
      'Whodata uses audit rules, not inotify. Check the audit backlog and lost counter. ' +
      'Realtime mode (not whodata) uses inotify and needs fs.inotify.max_user_watches above the watched directory count.',
      'auditctl -s\\nauditctl -l | grep -c wazuh_fim\\nsysctl fs.inotify.max_user_watches');
  }

  if (changed.some(p => p.key.endsWith('.debug') && getValue(p.key) > 0)) {
    addBlock(cont, 'warn-box', 'Debug is on. Revert to 0 after the test: debug output fills /var/ossec/logs quickly.', '');
  }

  if (['analysisd.rule_tree_memory_warning', 'analysisd.rule_tree_memory_limit'].some(k => getValue(k) !== ALL[k].default)) {
    addBlock(cont, 'info-box',
      'Rule tree thresholds are read at start. Check the computed node counts and any 7621/5108/5109 message:',
      "grep -E 'Rule tree|7621|5108|5109' /var/ossec/logs/ossec.log | tail");
  }

  if (getValue('remoted.send_buffer_size') !== ALL['remoted.send_buffer_size'].default) {
    addBlock(cont, 'info-box',
      'remoted.send_buffer_size is a user-space queue per agent. net.core.wmem_max does not limit it and needs no change.', '');
  }

  addBlock(cont, 'info-box', '3. Rollback: restore the previous file (or remove the changed lines) and restart wazuh-manager.', '');
}

buildNav();
buildPresets();
buildMain();
refreshNav();
</script>
</body>
</html>"""


def render_page():
    return (HTML_TEMPLATE
            .replace("__PARAMS__", json.dumps(PARAMS))
            .replace("__PRESETS__", json.dumps(PRESETS))
            .replace("__VERSION__", json.dumps(WAZUH_VERSION)))


class Server(ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind() calls socket.getfqdn(), which can block for seconds on reverse DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj), "application/json")

    def do_GET(self):
        if self.path == "/":
            self._send(200, render_page(), "text/html; charset=utf-8")
        elif self.path == "/api/params":
            self._json(200, PARAMS)
        elif self.path == "/api/presets":
            self._json(200, PRESETS)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/api/generate":
            return self._json(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 65536:
                return self._json(413, {"error": "request too large"})
            data = json.loads(self.rfile.read(length) or b"{}")
            values = data.get("values", {})
            if not isinstance(values, dict):
                raise ValueError
        except (ValueError, AttributeError):
            return self._json(400, {"error": "body must be JSON: {\"values\": {key: int}}"})
        clean, errors = validate(values)
        if errors:
            return self._json(400, {"errors": errors})
        self._json(200, {"config": generate(clean, changed_only=data.get("changed_only", True) is not False)})


def main():
    ap = argparse.ArgumentParser(description="Wazuh manager local_internal_options.conf tuner")
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address (default 127.0.0.1; the UI has no authentication)")
    ap.add_argument("--port", type=int, default=7437)
    ap.add_argument("--check", metavar="INTERNAL_OPTIONS_CONF",
                    help="compare built-in defaults with an internal_options.conf and exit")
    args = ap.parse_args()
    if args.check:
        sys.exit(check_defaults(args.check))
    server = Server((args.host, args.port), Handler)
    print(f"wazuh-tuner on http://{args.host}:{args.port}/ (Wazuh {WAZUH_VERSION} parameters)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
