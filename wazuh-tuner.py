#!/usr/bin/env python3
"""Wazuh local_internal_options.conf tuning UI.

Created by tick <tick@linuxmafia.pl>
"""
import json
from flask import Flask, render_template_string, request, jsonify

app = Flask(__name__)

PARAMS = {
    "analysisd": {
        "label": "Analysis Daemon (analysisd)",
        "desc": "Core event processing, decoding, rule matching.",
        "params": [
            {"key": "analysisd.event_threads", "default": 0, "min": 0, "max": 32, "type": "int",
             "desc": "Event decoder threads (0=auto). Increase on multi-core for high EPS.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.rule_matching_threads", "default": 0, "min": 0, "max": 32, "type": "int",
             "desc": "Rule evaluation threads (0=auto).",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.syscheck_threads", "default": 0, "min": 0, "max": 32, "type": "int",
             "desc": "FIM event decoder threads.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.syscollector_threads", "default": 0, "min": 0, "max": 32, "type": "int",
             "desc": "Syscollector decoder threads.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.dbsync_threads", "default": 0, "min": 0, "max": 32, "type": "int",
             "desc": "DB sync dispatcher threads.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.decode_event_queue_size", "default": 16384, "min": 128, "max": 2000000, "type": "int",
             "desc": "Event decode queue depth. Increase if wazuh-analysisd.state shows drops.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.decode_syscheck_queue_size", "default": 16384, "min": 128, "max": 2000000, "type": "int",
             "desc": "FIM decode queue depth.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.alerts_queue_size", "default": 16384, "min": 128, "max": 2000000, "type": "int",
             "desc": "Alerts output queue. Raise if alerts are dropped before writing.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.decode_output_queue_size", "default": 16384, "min": 128, "max": 2000000, "type": "int",
             "desc": "Output stage queue.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.archives_queue_size", "default": 16384, "min": 128, "max": 2000000, "type": "int",
             "desc": "Archives log queue.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.rlimit_nofile", "default": 458752, "min": 1024, "max": 1048576, "type": "int",
             "desc": "FD limit for analysisd process.",
             "sysctl": "fs.file-max must be higher than this value",
             "systemd": "LimitNOFILE in wazuh-manager.service override"},
            {"key": "analysisd.default_timeframe", "default": 360, "min": 60, "max": 360, "type": "int",
             "desc": "Rule correlation window in seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.decoder_order_size", "default": 256, "min": 32, "max": 1024, "type": "int",
             "desc": "Max fields per decoder order tag.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.min_rotate_interval", "default": 600, "min": 10, "max": 86400, "type": "int",
             "desc": "Min seconds between log rotations.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.state_interval", "default": 5, "min": 0, "max": 86400, "type": "int",
             "desc": "State file update interval seconds (0=off). Watch wazuh-analysisd.state for queue drops.",
             "sysctl": "", "systemd": ""},
            {"key": "analysisd.debug", "default": 0, "min": 0, "max": 2, "type": "int",
             "desc": "Debug verbosity (0=off, 1=basic, 2=verbose). Never leave at 2 in prod.",
             "sysctl": "", "systemd": ""},
        ]
    },
    "remoted": {
        "label": "Remote Daemon (remoted)",
        "desc": "Agent communication, TCP/UDP, message queuing.",
        "params": [
            {"key": "remoted.worker_pool", "default": 4, "min": 1, "max": 16, "type": "int",
             "desc": "Payload reception threads. Scale with agent count.",
             "sysctl": "", "systemd": ""},
            {"key": "remoted.sender_pool", "default": 8, "min": 1, "max": 64, "type": "int",
             "desc": "Shared file sender threads.",
             "sysctl": "", "systemd": ""},
            {"key": "remoted.request_pool", "default": 1024, "min": 1, "max": 4096, "type": "int",
             "desc": "Parallel request dispatchers.",
             "sysctl": "", "systemd": ""},
            {"key": "remoted.send_buffer_size", "default": 131072, "min": 65536, "max": 1048576, "type": "int",
             "desc": "Per-agent TCP send queue bytes.",
             "sysctl": "net.core.wmem_max must be >= this value",
             "systemd": ""},
            {"key": "remoted.ctrl_msg_queue_size", "default": 16384, "min": 1024, "max": 1048576, "type": "int",
             "desc": "Max queued control messages.",
             "sysctl": "", "systemd": ""},
            {"key": "remoted.rlimit_nofile", "default": 16384, "min": 1024, "max": 1048576, "type": "int",
             "desc": "FD limit for remoted. One FD per connected agent plus extras.",
             "sysctl": "fs.file-max must accommodate this",
             "systemd": "LimitNOFILE in wazuh-manager.service override"},
            {"key": "remoted.receive_chunk", "default": 4096, "min": 1024, "max": 16384, "type": "int",
             "desc": "TCP recv buffer bytes.",
             "sysctl": "net.core.rmem_max",
             "systemd": ""},
            {"key": "remoted.send_chunk", "default": 4096, "min": 512, "max": 16384, "type": "int",
             "desc": "TCP send buffer bytes.",
             "sysctl": "net.core.wmem_max",
             "systemd": ""},
            {"key": "remoted.tcp_keepidle", "default": 30, "min": 1, "max": 7200, "type": "int",
             "desc": "Idle seconds before TCP keepalive probes start.",
             "sysctl": "net.ipv4.tcp_keepalive_time (kernel default; remoted overrides per-socket)",
             "systemd": ""},
            {"key": "remoted.tcp_keepintvl", "default": 10, "min": 1, "max": 100, "type": "int",
             "desc": "Seconds between keepalive probes.",
             "sysctl": "net.ipv4.tcp_keepalive_intvl",
             "systemd": ""},
            {"key": "remoted.tcp_keepcnt", "default": 3, "min": 1, "max": 50, "type": "int",
             "desc": "Probes before dropping connection.",
             "sysctl": "net.ipv4.tcp_keepalive_probes",
             "systemd": ""},
            {"key": "remoted.keyupdate_interval", "default": 10, "min": 1, "max": 3600, "type": "int",
             "desc": "Seconds to reload client.keys after change.",
             "sysctl": "", "systemd": ""},
            {"key": "remoted.shared_reload", "default": 10, "min": 1, "max": 18000, "type": "int",
             "desc": "Shared file reload interval seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "remoted.state_interval", "default": 5, "min": 0, "max": 86400, "type": "int",
             "desc": "State file update interval (watch wazuh-remoted.state for discarded events).",
             "sysctl": "", "systemd": ""},
            {"key": "remoted.debug", "default": 0, "min": 0, "max": 2, "type": "int",
             "desc": "Debug verbosity.",
             "sysctl": "", "systemd": ""},
        ]
    },
    "wazuh_db": {
        "label": "Wazuh DB (wazuh-db)",
        "desc": "SQLite agent database daemon.",
        "params": [
            {"key": "wazuh_db.worker_pool_size", "default": 8, "min": 1, "max": 32, "type": "int",
             "desc": "Worker threads. Scale with agent count.",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_db.open_db_limit", "default": 64, "min": 1, "max": 4096, "type": "int",
             "desc": "Max simultaneously open SQLite DBs (LRU eviction above limit).",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_db.rlimit_nofile", "default": 65536, "min": 1024, "max": 1048576, "type": "int",
             "desc": "FD limit for wazuh-db.",
             "sysctl": "fs.file-max must accommodate this",
             "systemd": "LimitNOFILE in wazuh-manager.service override"},
            {"key": "wazuh_db.commit_time_min", "default": 10, "min": 1, "max": 3600, "type": "int",
             "desc": "Min seconds before DB commit (lower = more I/O, less data loss on crash).",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_db.commit_time_max", "default": 60, "min": 1, "max": 3600, "type": "int",
             "desc": "Max seconds before forced commit.",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_db.max_fragmentation", "default": 90, "min": 0, "max": 100, "type": "int",
             "desc": "DB fragmentation % ceiling before VACUUM.",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_db.fragmentation_threshold", "default": 75, "min": 0, "max": 100, "type": "int",
             "desc": "Fragmentation % to trigger defrag.",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_db.check_fragmentation_interval", "default": 7200, "min": 1, "max": 30758400, "type": "int",
             "desc": "Fragmentation check interval seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_db.debug", "default": 0, "min": 0, "max": 2, "type": "int",
             "desc": "Debug verbosity.",
             "sysctl": "", "systemd": ""},
        ]
    },
    "logcollector": {
        "label": "Log Collector (logcollector)",
        "desc": "File tailing, journal reading, command output collection.",
        "params": [
            {"key": "logcollector.input_threads", "default": 4, "min": 1, "max": 128, "type": "int",
             "desc": "File reader threads.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.queue_size", "default": 1024, "min": 128, "max": 220000, "type": "int",
             "desc": "Output queue per socket. Raise if logcollector.state shows drops.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.max_lines", "default": 10000, "min": 100, "max": 100000, "type": "int",
             "desc": "Max lines read per file per poll loop.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.max_files", "default": 1000, "min": 1, "max": 100000, "type": "int",
             "desc": "Max simultaneously monitored files.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.rlimit_nofile", "default": 1100, "min": 1024, "max": 1048576, "type": "int",
             "desc": "FD limit -- must be > max_files + overhead.",
             "sysctl": "fs.file-max must accommodate this",
             "systemd": "LimitNOFILE in wazuh-manager.service override"},
            {"key": "logcollector.loop_timeout", "default": 2, "min": 1, "max": 120, "type": "int",
             "desc": "File poll interval seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.vcheck_files", "default": 64, "min": 0, "max": 1024, "type": "int",
             "desc": "File existence check interval seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.sock_fail_time", "default": 300, "min": 1, "max": 3600, "type": "int",
             "desc": "Reconnect delay on socket failure seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.state_interval", "default": 60, "min": 0, "max": 3600, "type": "int",
             "desc": "Stats file update interval seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "logcollector.debug", "default": 0, "min": 0, "max": 2, "type": "int",
             "desc": "Debug verbosity.",
             "sysctl": "", "systemd": ""},
        ]
    },
    "syscheck": {
        "label": "FIM / Syscheck",
        "desc": "File integrity monitoring parameters.",
        "params": [
            {"key": "syscheck.rt_delay", "default": 10, "min": 1, "max": 1000, "type": "int",
             "desc": "Realtime alert debounce milliseconds (avoid storm on mass writes).",
             "sysctl": "", "systemd": ""},
            {"key": "syscheck.max_audit_entries", "default": 256, "min": 1, "max": 4096, "type": "int",
             "desc": "Max Linux whodata (auditd) monitored dirs.",
             "sysctl": "fs.inotify.max_user_watches must be >= this for realtime mode",
             "systemd": ""},
            {"key": "syscheck.default_max_depth", "default": 256, "min": 1, "max": 320, "type": "int",
             "desc": "Max directory recursion depth.",
             "sysctl": "", "systemd": ""},
            {"key": "syscheck.symlink_scan_interval", "default": 600, "min": 1, "max": 2592000, "type": "int",
             "desc": "Symlink check interval seconds.",
             "sysctl": "", "systemd": ""},
            {"key": "syscheck.file_max_size", "default": 1024, "min": 0, "max": 4095, "type": "int",
             "desc": "Max file size MiB for hashing (0=unlimited).",
             "sysctl": "", "systemd": ""},
            {"key": "syscheck.debug", "default": 0, "min": 0, "max": 2, "type": "int",
             "desc": "Debug verbosity.",
             "sysctl": "", "systemd": ""},
        ]
    },
    "wazuh_modules": {
        "label": "Wazuh Modules",
        "desc": "Vulnerability detection, SCA, Syscollector, and other modules.",
        "params": [
            {"key": "wazuh_modules.max_eps", "default": 100, "min": 1, "max": 1000, "type": "int",
             "desc": "Max events/second from all modules combined.",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_modules.task_nice", "default": 10, "min": -20, "max": 19, "type": "int",
             "desc": "Process nice value (10=background, 0=normal, -20=highest priority).",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_modules.rlimit_nofile", "default": 8192, "min": 1024, "max": 1048576, "type": "int",
             "desc": "FD limit for wazuh-modulesd.",
             "sysctl": "fs.file-max must accommodate this",
             "systemd": "LimitNOFILE in wazuh-manager.service override"},
            {"key": "wazuh_modules.kill_timeout", "default": 10, "min": 0, "max": 3600, "type": "int",
             "desc": "Grace period seconds before SIGKILL on module stop.",
             "sysctl": "", "systemd": ""},
            {"key": "wazuh_modules.debug", "default": 0, "min": 0, "max": 2, "type": "int",
             "desc": "Debug verbosity.",
             "sysctl": "", "systemd": ""},
        ]
    },
    "monitord": {
        "label": "Monitor Daemon (monitord)",
        "desc": "Log rotation, agent connectivity monitoring.",
        "params": [
            {"key": "monitord.keep_log_days", "default": 31, "min": 0, "max": 500, "type": "int",
             "desc": "Days to retain rotated logs.",
             "sysctl": "", "systemd": ""},
            {"key": "monitord.size_rotate", "default": 512, "min": 0, "max": 4096, "type": "int",
             "desc": "Max log size MB before rotation.",
             "sysctl": "", "systemd": ""},
            {"key": "monitord.daily_rotations", "default": 12, "min": 1, "max": 256, "type": "int",
             "desc": "Max log rotations per day.",
             "sysctl": "", "systemd": ""},
            {"key": "monitord.compress", "default": 1, "min": 0, "max": 1, "type": "int",
             "desc": "Compress rotated logs (1=yes).",
             "sysctl": "", "systemd": ""},
            {"key": "monitord.rotate_log", "default": 1, "min": 0, "max": 1, "type": "int",
             "desc": "Enable daily log rotation.",
             "sysctl": "", "systemd": ""},
            {"key": "monitord.day_wait", "default": 10, "min": 0, "max": 600, "type": "int",
             "desc": "Seconds delay before compressing/signing rotated logs.",
             "sysctl": "", "systemd": ""},
            {"key": "monitord.debug", "default": 0, "min": 0, "max": 2, "type": "int",
             "desc": "Debug verbosity.",
             "sysctl": "", "systemd": ""},
        ]
    },
    "wazuh": {
        "label": "Global (wazuh)",
        "desc": "Global wazuh daemon settings.",
        "params": [
            {"key": "wazuh.thread_stack_size", "default": 8192, "min": 2048, "max": 65536, "type": "int",
             "desc": "Thread stack size KiB. Raise only if seeing stack overflows in logs.",
             "sysctl": "",
             "systemd": "LimitSTACK in systemd unit if raised above OS default"},
        ]
    },
}

PRESETS = {
    "default": {
        "label": "Default (stock)",
        "desc": "All Wazuh defaults. Clean baseline.",
        "values": {}
    },
    "small": {
        "label": "Small (<500 agents, <5k EPS)",
        "desc": "Conservative settings for smaller deployments.",
        "values": {
            "analysisd.event_threads": 2,
            "analysisd.rule_matching_threads": 2,
            "analysisd.decode_event_queue_size": 32768,
            "analysisd.alerts_queue_size": 32768,
            "remoted.worker_pool": 4,
            "wazuh_db.worker_pool_size": 8,
            "logcollector.queue_size": 4096,
        }
    },
    "medium": {
        "label": "Medium (500-2000 agents, 5-50k EPS)",
        "desc": "Balanced performance for mid-size MSSP deployments.",
        "values": {
            "analysisd.event_threads": 4,
            "analysisd.rule_matching_threads": 4,
            "analysisd.syscheck_threads": 2,
            "analysisd.dbsync_threads": 2,
            "analysisd.decode_event_queue_size": 65536,
            "analysisd.decode_syscheck_queue_size": 32768,
            "analysisd.alerts_queue_size": 65536,
            "analysisd.decode_output_queue_size": 32768,
            "analysisd.rlimit_nofile": 458752,
            "remoted.worker_pool": 8,
            "remoted.sender_pool": 16,
            "remoted.request_pool": 2048,
            "remoted.send_buffer_size": 262144,
            "remoted.rlimit_nofile": 65536,
            "wazuh_db.worker_pool_size": 16,
            "wazuh_db.open_db_limit": 256,
            "wazuh_db.rlimit_nofile": 65536,
            "wazuh_db.commit_time_min": 5,
            "wazuh_db.commit_time_max": 30,
            "logcollector.input_threads": 8,
            "logcollector.queue_size": 16384,
            "logcollector.max_lines": 50000,
            "logcollector.rlimit_nofile": 8192,
        }
    },
    "large": {
        "label": "Large (>2000 agents, >50k EPS)",
        "desc": "Aggressive tuning for high-scale Beyond/MSSP stacks.",
        "values": {
            "analysisd.event_threads": 8,
            "analysisd.rule_matching_threads": 8,
            "analysisd.syscheck_threads": 4,
            "analysisd.syscollector_threads": 4,
            "analysisd.dbsync_threads": 4,
            "analysisd.decode_event_queue_size": 131072,
            "analysisd.decode_syscheck_queue_size": 65536,
            "analysisd.alerts_queue_size": 131072,
            "analysisd.archives_queue_size": 65536,
            "analysisd.decode_output_queue_size": 65536,
            "analysisd.rlimit_nofile": 524288,
            "remoted.worker_pool": 16,
            "remoted.sender_pool": 32,
            "remoted.request_pool": 4096,
            "remoted.send_buffer_size": 524288,
            "remoted.ctrl_msg_queue_size": 65536,
            "remoted.rlimit_nofile": 131072,
            "wazuh_db.worker_pool_size": 24,
            "wazuh_db.open_db_limit": 1024,
            "wazuh_db.rlimit_nofile": 131072,
            "wazuh_db.commit_time_min": 3,
            "wazuh_db.commit_time_max": 15,
            "logcollector.input_threads": 16,
            "logcollector.queue_size": 65536,
            "logcollector.max_lines": 100000,
            "logcollector.rlimit_nofile": 32768,
        }
    },
    "debug": {
        "label": "Debug (temporary, never prod)",
        "desc": "All daemons at debug=1. Find issues then revert.",
        "values": {
            "analysisd.debug": 1,
            "remoted.debug": 1,
            "wazuh_db.debug": 1,
            "logcollector.debug": 1,
            "syscheck.debug": 1,
            "wazuh_modules.debug": 1,
            "monitord.debug": 1,
        }
    },
}

# Embed data as JSON in page — all rendering done via safe DOM textContent, no user input in innerHTML
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Wazuh Tuner</title>
<style>
:root {
  --bg:#0d1117;--surface:#161b22;--border:#30363d;
  --text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;
  --warn:#d29922;--danger:#f85149;--ok:#3fb950;--code-bg:#010409;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;font-size:14px;}
.layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh;}
.sidebar{background:var(--surface);border-right:1px solid var(--border);padding:16px;position:sticky;top:0;height:100vh;overflow-y:auto;}
.sidebar h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;}
.nav-item{display:block;padding:8px 10px;border-radius:6px;color:var(--muted);text-decoration:none;font-size:13px;cursor:pointer;margin-bottom:2px;border:none;background:none;width:100%;text-align:left;}
.nav-item:hover,.nav-item.active{background:rgba(88,166,255,.15);color:var(--accent);}
.preset-btn{display:block;width:100%;text-align:left;padding:8px 10px;border-radius:6px;border:1px solid var(--border);background:var(--bg);color:var(--text);font-size:12px;cursor:pointer;margin-bottom:4px;}
.preset-btn:hover{border-color:var(--accent);color:var(--accent);}
.main{padding:24px 32px;}
.section{display:none;}
.section.active{display:block;}
.section-header{margin-bottom:20px;}
.section-header h1{font-size:20px;font-weight:600;margin-bottom:4px;}
.section-header p{color:var(--muted);font-size:13px;}
.param-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px;}
.param-card.changed{border-color:var(--accent);}
.param-key{font-family:monospace;font-size:13px;color:var(--accent);margin-bottom:4px;}
.param-badge{display:inline-block;font-size:11px;padding:2px 6px;border-radius:10px;background:rgba(88,166,255,.15);color:var(--accent);margin-left:6px;}
.param-desc{font-size:12px;color:var(--muted);margin-bottom:10px;line-height:1.5;}
.param-hint{font-size:11px;margin-top:6px;padding:6px 8px;border-radius:4px;}
.param-hint.sysctl{background:rgba(210,153,34,.1);border-left:3px solid var(--warn);color:var(--warn);}
.param-hint.systemd{background:rgba(63,185,80,.1);border-left:3px solid var(--ok);color:var(--ok);}
.input-row{display:flex;align-items:center;gap:12px;}
.input-row input[type=range]{flex:1;accent-color:var(--accent);}
.input-row input[type=number]{width:110px;background:var(--code-bg);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 8px;font-size:13px;}
.range-bounds{font-size:11px;color:var(--muted);white-space:nowrap;}
.radio-row{display:flex;gap:16px;}
.radio-row label{display:flex;align-items:center;gap:4px;cursor:pointer;font-size:13px;}
.output-section{background:var(--code-bg);border:1px solid var(--border);border-radius:8px;padding:20px;}
.output-section pre{color:var(--ok);font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;}
.btn{padding:8px 16px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500;}
.btn-primary{background:var(--accent);color:#000;}
.btn-primary:hover{opacity:.85;}
.btn-secondary{background:var(--surface);color:var(--text);border:1px solid var(--border);}
.btn-secondary:hover{border-color:var(--accent);}
.btn-danger{background:rgba(248,81,73,.15);color:var(--danger);border:1px solid var(--danger);}
.toolbar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap;align-items:center;}
.tab-bar{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);}
.tab{padding:8px 16px;cursor:pointer;color:var(--muted);font-size:13px;border-bottom:2px solid transparent;margin-bottom:-1px;}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);}
.tab-content{display:none;}
.tab-content.active{display:block;}
.warn-box{background:rgba(210,153,34,.1);border:1px solid var(--warn);border-radius:6px;padding:12px 16px;margin-bottom:16px;font-size:12px;color:var(--warn);}
.info-box{background:rgba(88,166,255,.1);border:1px solid var(--accent);border-radius:6px;padding:12px 16px;margin-bottom:16px;font-size:12px;color:var(--accent);}
.hint-label{font-size:12px;font-weight:600;margin-bottom:6px;}
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
    </div>
  </div>
  <div class="main" id="main"></div>
</div>
<script>
const PARAMS = """ + json.dumps(PARAMS) + """;
const PRESETS = """ + json.dumps(PRESETS) + """;
const SECTION_KEYS = """ + json.dumps(list(PARAMS.keys())) + """;
let values = {};

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function getValue(key) {
  const all = Object.values(PARAMS).flatMap(s => s.params);
  const p = all.find(x => x.key === key);
  return values[key] !== undefined ? values[key] : p.default;
}

function buildNav() {
  const nav = document.getElementById('nav');
  const sections = [...SECTION_KEYS, 'output', 'system'];
  const labels = {...Object.fromEntries(SECTION_KEYS.map(k => [k, PARAMS[k].label.split(' (')[0]])),
    output: 'Generate Config', system: 'System Hints'};
  sections.forEach((id, i) => {
    const btn = el('button', 'nav-item' + (i === 0 ? ' active' : ''));
    btn.textContent = (id === 'output' ? '📄 ' : id === 'system' ? '🖥 ' : '') + labels[id];
    btn.dataset.section = id;
    btn.addEventListener('click', () => showSection(id));
    nav.appendChild(btn);
  });
}

function buildPresets() {
  const cont = document.getElementById('presets');
  Object.entries(PRESETS).forEach(([id, preset]) => {
    const btn = el('button', 'preset-btn');
    btn.textContent = preset.label;
    btn.title = preset.desc;
    btn.addEventListener('click', () => applyPreset(id));
    cont.appendChild(btn);
  });
}

function buildParamCard(p) {
  const card = el('div', 'param-card');
  card.id = 'card-' + p.key;

  const keyLine = el('div', 'param-key');
  keyLine.textContent = p.key;
  const badge = el('span', 'param-badge', 'default: ' + p.default);
  keyLine.appendChild(badge);
  card.appendChild(keyLine);

  card.appendChild(el('div', 'param-desc', p.desc));

  const val = getValue(p.key);
  const isToggle = p.min === 0 && p.max === 1;
  const isDebug = p.min === 0 && p.max === 2;

  if (isToggle || isDebug) {
    const row = el('div', 'radio-row');
    const opts = isDebug ? [0, 1, 2] : [0, 1];
    opts.forEach(o => {
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
    });
    card.appendChild(row);
  } else {
    const row = el('div', 'input-row');

    const minSpan = el('span', 'range-bounds', String(p.min));
    const range = document.createElement('input');
    range.type = 'range';
    range.id = 'range-' + p.key;
    range.min = p.min;
    range.max = p.max;
    range.value = val;
    const num = document.createElement('input');
    num.type = 'number';
    num.id = 'num-' + p.key;
    num.min = p.min;
    num.max = p.max;
    num.value = val;
    const maxSpan = el('span', 'range-bounds', String(p.max));

    range.addEventListener('input', () => { num.value = range.value; setVal(p.key, parseInt(range.value)); });
    num.addEventListener('input', () => { range.value = num.value; setVal(p.key, parseInt(num.value)); });

    row.appendChild(minSpan);
    row.appendChild(range);
    row.appendChild(num);
    row.appendChild(maxSpan);
    card.appendChild(row);
  }

  if (p.sysctl) {
    const hint = el('div', 'param-hint sysctl', 'sysctl: ' + p.sysctl);
    card.appendChild(hint);
  }
  if (p.systemd) {
    const hint = el('div', 'param-hint systemd', 'systemd: ' + p.systemd);
    card.appendChild(hint);
  }

  if (val !== p.default) card.classList.add('changed');
  return card;
}

function buildSection(sectionId) {
  const section = PARAMS[sectionId];
  const div = el('div', 'section');
  div.id = 'section-' + sectionId;

  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, section.label));
  hdr.appendChild(el('p', null, section.desc));
  div.appendChild(hdr);

  section.params.forEach(p => div.appendChild(buildParamCard(p)));
  return div;
}

function buildOutputSection() {
  const div = el('div', 'section');
  div.id = 'section-output';

  const hdr = el('div', 'section-header');
  hdr.appendChild(el('h1', null, 'Generate Config'));
  hdr.appendChild(el('p', null, 'Preview and copy local_internal_options.conf'));
  div.appendChild(hdr);

  const tabBar = el('div', 'tab-bar');
  ['conf', 'diff'].forEach((t, i) => {
    const tab = el('div', 'tab' + (i === 0 ? ' active' : ''), t === 'conf' ? 'Full config' : 'Changed only');
    tab.dataset.tab = t;
    tab.addEventListener('click', () => switchTab(t));
    tabBar.appendChild(tab);
  });
  div.appendChild(tabBar);

  ['conf', 'diff'].forEach((t, i) => {
    const tc = el('div', 'tab-content' + (i === 0 ? ' active' : ''));
    tc.id = 'tab-' + t;
    if (t === 'conf') {
      const toolbar = el('div', 'toolbar');
      const copyBtn = el('button', 'btn btn-primary', 'Copy to clipboard');
      copyBtn.id = 'copy-btn';
      copyBtn.addEventListener('click', copyConf);
      const dlBtn = el('button', 'btn btn-secondary', 'Download');
      dlBtn.addEventListener('click', downloadConf);
      const resetBtn = el('button', 'btn btn-danger', 'Reset all to defaults');
      resetBtn.addEventListener('click', () => { values = {}; location.reload(); });
      toolbar.appendChild(copyBtn);
      toolbar.appendChild(dlBtn);
      toolbar.appendChild(resetBtn);
      tc.appendChild(toolbar);
    }
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
  hdr.appendChild(el('h1', null, 'System-Level Hints'));
  hdr.appendChild(el('p', null, 'Kernel, systemd, and limits changes to support your tuning.'));
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
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
  document.getElementById('section-' + id).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(b => {
    if (b.dataset.section === id) b.classList.add('active');
  });
  if (id === 'output') updateOutput();
  if (id === 'system') updateSystemHints();
}

function setVal(key, val) {
  const all = Object.values(PARAMS).flatMap(s => s.params);
  const p = all.find(x => x.key === key);
  val = isNaN(val) ? p.default : val;
  values[key] = val;
  const card = document.getElementById('card-' + key);
  if (card) card.classList.toggle('changed', val !== p.default);
}

function generateConf(changedOnly) {
  const lines = [
    '# /var/ossec/etc/local_internal_options.conf',
    '# Generated by wazuh-tuner -- DO NOT edit internal_options.conf directly',
    '# Date: ' + new Date().toISOString().split('T')[0],
    '',
  ];
  Object.entries(PARAMS).forEach(([sid, section]) => {
    const ps = section.params.filter(p => changedOnly ? getValue(p.key) !== p.default : true);
    if (!ps.length) return;
    lines.push('# --- ' + section.label + ' ---');
    ps.forEach(p => lines.push(p.key + '=' + getValue(p.key)));
    lines.push('');
  });
  if (changedOnly && lines.length <= 5) return '# No parameters changed from defaults.';
  return lines.join('\\n');
}

function updateOutput() {
  document.getElementById('out-conf').textContent = generateConf(false);
  document.getElementById('out-diff').textContent = generateConf(true);
}

function switchTab(tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelector('[data-tab="' + tab + '"]').classList.add('active');
  document.getElementById('tab-' + tab).classList.add('active');
}

function copyConf() {
  navigator.clipboard.writeText(generateConf(false)).then(() => {
    const btn = document.getElementById('copy-btn');
    btn.textContent = 'Copied!';
    btn.style.background = '#3fb950';
    setTimeout(() => { btn.textContent = 'Copy to clipboard'; btn.style.background = ''; }, 1500);
  });
}

function downloadConf() {
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(generateConf(false));
  a.download = 'local_internal_options.conf';
  a.click();
}

function applyPreset(id) {
  const preset = PRESETS[id];
  values = { ...preset.values };
  const all = Object.values(PARAMS).flatMap(s => s.params);
  all.forEach(p => {
    const v = getValue(p.key);
    const range = document.getElementById('range-' + p.key);
    const num = document.getElementById('num-' + p.key);
    if (range) range.value = v;
    if (num) num.value = v;
    document.querySelectorAll('input[name="' + p.key + '"]').forEach(r => { r.checked = parseInt(r.value) === v; });
    const card = document.getElementById('card-' + p.key);
    if (card) card.classList.toggle('changed', v !== p.default);
  });
}

function addBlock(parent, cls, labelText, codeText) {
  const box = el('div', cls, labelText);
  parent.appendChild(box);
  const out = el('div', 'output-section');
  out.style.marginBottom = '16px';
  const pre = el('pre');
  pre.textContent = codeText;
  out.appendChild(pre);
  parent.appendChild(out);
}

function updateSystemHints() {
  const cont = document.getElementById('sys-content');
  while (cont.firstChild) cont.removeChild(cont.firstChild);

  const maxFD = Math.max(
    getValue('analysisd.rlimit_nofile'),
    getValue('remoted.rlimit_nofile'),
    getValue('wazuh_db.rlimit_nofile'),
    getValue('wazuh_modules.rlimit_nofile'),
    getValue('logcollector.rlimit_nofile'),
  );
  const defaultMaxFD = Math.max(458752, 16384, 65536, 8192, 1100);
  const fdChanged = maxFD !== defaultMaxFD;

  const sendBuf = getValue('remoted.send_buffer_size');
  const netChanged = sendBuf > 131072;
  const auditChanged = getValue('syscheck.max_audit_entries') > 256;
  const stackChanged = getValue('wazuh.thread_stack_size') > 8192;
  const anyChanged = fdChanged || netChanged || auditChanged;

  if (!anyChanged) {
    const box = el('div', 'info-box', 'No system-level changes needed for current tuning. Tune parameters first.');
    cont.appendChild(box);
    return;
  }

  // sysctl
  const sysctlLines = [];
  if (fdChanged) {
    sysctlLines.push('fs.file-max = ' + (maxFD * 3));
    sysctlLines.push('fs.nr_open = ' + (maxFD * 3));
  }
  if (netChanged) {
    sysctlLines.push('net.core.wmem_max = ' + (sendBuf * 2));
    sysctlLines.push('net.core.rmem_max = ' + (sendBuf * 2));
    sysctlLines.push('net.core.wmem_default = ' + sendBuf);
    sysctlLines.push('net.core.rmem_default = ' + sendBuf);
    sysctlLines.push('net.core.somaxconn = 65535');
    sysctlLines.push('net.ipv4.tcp_max_syn_backlog = 65535');
  }
  if (auditChanged) {
    sysctlLines.push('fs.inotify.max_user_watches = 524288');
    sysctlLines.push('fs.inotify.max_queued_events = 32768');
  }
  if (sysctlLines.length) {
    addBlock(cont, 'warn-box',
      'Apply to /etc/sysctl.d/99-wazuh-tuner.conf then run: sysctl --system',
      sysctlLines.join('\\n'));
  }

  // limits.conf
  if (fdChanged) {
    addBlock(cont, 'info-box', '/etc/security/limits.conf additions:',
      'wazuh  soft  nofile  ' + maxFD + '\\n' +
      'wazuh  hard  nofile  ' + maxFD + '\\n' +
      'root   soft  nofile  ' + maxFD + '\\n' +
      'root   hard  nofile  ' + maxFD);
  }

  // systemd override
  const unitLines = ['[Service]', 'LimitNOFILE=' + maxFD, 'LimitNPROC=65536'];
  if (stackChanged) unitLines.push('LimitSTACK=' + (getValue('wazuh.thread_stack_size') * 1024));
  addBlock(cont, 'info-box',
    'systemd override: /etc/systemd/system/wazuh-manager.service.d/override.conf\\nThen: systemctl daemon-reload && systemctl restart wazuh-manager',
    unitLines.join('\\n'));

  // apply order
  addBlock(cont, 'warn-box',
    'Apply order:\\n' +
    '1. sysctl.d/99-wazuh-tuner.conf -> sysctl --system\\n' +
    '2. /etc/security/limits.conf (pam_limits must be in /etc/pam.d/common-session)\\n' +
    '3. systemd override -> systemctl daemon-reload\\n' +
    '4. /var/ossec/etc/local_internal_options.conf (copy from Generate Config)\\n' +
    '5. systemctl restart wazuh-manager\\n' +
    '6. Verify: grep drops /var/ossec/var/run/wazuh-analysisd.state', '');
}

buildNav();
buildPresets();
buildMain();
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/params")
def api_params():
    return jsonify(PARAMS)


@app.route("/api/presets")
def api_presets():
    return jsonify(PRESETS)


@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.json or {}
    user_values = data.get("values", {})
    lines = [
        "# /var/ossec/etc/local_internal_options.conf",
        "# Generated by wazuh-tuner",
        "",
    ]
    for section_id, section in PARAMS.items():
        section_lines = []
        for p in section["params"]:
            v = user_values.get(p["key"], p["default"])
            if str(v) != str(p["default"]):
                section_lines.append(f"{p['key']}={v}")
        if section_lines:
            lines.append(f"# --- {section['label']} ---")
            lines.extend(section_lines)
            lines.append("")
    return jsonify({"config": "\n".join(lines)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7437, debug=False)
