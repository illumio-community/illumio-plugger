#!/usr/bin/env python3
"""
flowpilot — run the FlowPilot flow collector under plugger.

Maps plugger settings to FLOWPILOT_* variables, supervises the collector as a
child process, polls its local /stats endpoint, serves an ingestion-health
dashboard and raises plugger notifications when exporters go silent, no flows
arrive, or uploads to the PCE fail.
"""

import collections
import json
import os
import subprocess
import threading
import time
from datetime import datetime, timezone

import requests

from plugger_sdk import Plugin

app = Plugin("flowpilot")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BINARY = "/usr/local/bin/flowlink"
STATS_PORT = 9180
STATS_URL = f"http://127.0.0.1:{STATS_PORT}"
DATA_DIR = "/data"
PLUGIN_DIR = os.path.join(DATA_DIR, "plugin")
HISTORY_FILE = os.path.join(PLUGIN_DIR, "history.json")
ALERTS_FILE = os.path.join(PLUGIN_DIR, "alerts.json")
EXPORTERS_FILE = os.path.join(PLUGIN_DIR, "exporters.json")

POLL_SECONDS = 5
HISTORY_INTERVAL = 60
HISTORY_MAX = 1440  # 24h at one point per minute
EXPORTER_PRUNE_SECONDS = 7 * 24 * 3600

COLLECTORS = ("NETFLOW", "IPFIX", "SFLOW", "TEXT")
TEXT_FIELDS = (
    "SRC_IP", "DST_IP", "DST_PORT", "PROTOCOL", "ICMP_TYPE", "ICMP_CODE",
    "OCTETS", "TIMESTAMP", "TIMESTAMP_FORMAT", "ONLY_RECS",
    "FIELD_SEPARATOR", "ATTRIBUTE_SEPARATOR",
)
UNMANAGED_FIELDS = (
    "DRY_RUN", "NETWORKS", "MIN_FLOWS", "MAX_CREATES_PER_WINDOW",
    "MAX_CREATES_PER_DAY", "LABEL_RULES",
)
ERROR_MARKERS = ("is not valid", "is set but", "Unable to", "Error:", "exit")
CONTAINER_PORTS = {"netflow": 2055, "ipfix": 4739, "sflow": 6343, "text": 514}


def _int_env(name, default):
    try:
        return int(app.env(name, str(default)).strip())
    except ValueError:
        return default


def _bool_env(name, default=False):
    v = app.env(name, "true" if default else "false").strip().lower()
    return v in ("1", "true", "yes", "on")


SILENT_MINUTES = max(1, _int_env("SILENT_EXPORTER_MINUTES", 15))
SILENT_SECONDS = SILENT_MINUTES * 60
START_TIME = time.time()

stop = threading.Event()
lock = threading.RLock()

state = {
    "stats": None,
    "stats_ok": False,
    "last_poll": None,
    "status_line": "Starting FlowPilot...",
    "status_level": "warn",
    "config_error": None,
}
history = []      # [{t, total_fps, per_exporter}]
alert_state = {}  # {condition: bool}
exporters = {}    # "collector|addr" -> tracking record
_proc = None
_proc_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Persistence helpers
# ---------------------------------------------------------------------------

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except Exception as e:
        app.log.warning("Could not read %s: %s", path, e)
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
    except Exception as e:
        app.log.warning("Could not write %s: %s", path, e)


# ---------------------------------------------------------------------------
# FlowPilot environment
# ---------------------------------------------------------------------------

def build_flowpilot_env():
    env = {
        "FLOWPILOT_STATS_HTTP_LISTEN": f"127.0.0.1:{STATS_PORT}",
        "FLOWPILOT_DATA_DIRECTORY": os.path.join(DATA_DIR, "flowpilot"),
        "FLOWPILOT_STATS_IDLE_WARN_SECONDS": str(SILENT_SECONDS),
        "FLOWPILOT_AGGREGATION_MINUTES": app.env("AGGREGATION_MINUTES", "10").strip() or "10",
        "FLOWPILOT_VERIFY_PCE_CERT": app.env("VERIFY_PCE_CERT", "true").strip() or "true",
    }
    for c in COLLECTORS:
        if _bool_env(f"{c}_ENABLED", c == "NETFLOW"):
            port = app.env(f"{c}_PORT", "").strip() or str(CONTAINER_PORTS[c.lower()])
            if port:
                env[f"FLOWPILOT_{c}_PORTS"] = port
            remote = app.env(f"{c}_REMOTE_ADDRS", "").strip()
            if remote:
                env[f"FLOWPILOT_{c}_REMOTE_ADDRS"] = remote
    if _bool_env("TEXT_ENABLED"):
        for f in TEXT_FIELDS:
            v = app.env(f"TEXT_{f}", "")
            # Separators are passed through untrimmed (they may be whitespace).
            if f.endswith("SEPARATOR"):
                if v != "":
                    env[f"FLOWPILOT_TEXT_{f}"] = v
            elif v.strip():
                env[f"FLOWPILOT_TEXT_{f}"] = v.strip()
    if _bool_env("UNMANAGED_ENABLED"):
        env["FLOWPILOT_UNMANAGED_ENABLED"] = "true"
        for f in UNMANAGED_FIELDS:
            v = app.env(f"UNMANAGED_{f}", "").strip()
            if v:
                env[f"FLOWPILOT_UNMANAGED_{f}"] = v
    return env


def collectors_enabled():
    return [c.lower() for c in COLLECTORS if _bool_env(f"{c}_ENABLED", c == "NETFLOW")]


# ---------------------------------------------------------------------------
# Supervisor
# ---------------------------------------------------------------------------

def child_running():
    with _proc_lock:
        return _proc is not None and _proc.poll() is None


def _terminate_child(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.log.warning("FlowPilot did not stop in 10s, killing")
            proc.kill()
            proc.wait(timeout=5)
    except Exception as e:
        app.log.warning("Error stopping FlowPilot: %s", e)


def supervise():
    global _proc
    backoff = 1
    while not stop.is_set():
        ring = collections.deque(maxlen=20)
        error_lines = []
        started = time.time()
        try:
            proc = subprocess.Popen(
                [BINARY], env=os.environ.copy(), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
        except Exception as e:
            msg = f"Cannot start {BINARY}: {e}"
            app.log.error(msg)
            with lock:
                state["config_error"] = msg
            if stop.wait(30):
                return
            continue

        with _proc_lock:
            _proc = proc
        app.log.info("FlowPilot started (pid %d)", proc.pid)

        def _pump(p=proc):
            try:
                for line in p.stdout:
                    line = line.rstrip("\n")
                    print(line, flush=True)
                    ring.append(line)
                    if any(m in line for m in ERROR_MARKERS):
                        error_lines.append(line)
            except Exception:
                pass

        pump = threading.Thread(target=_pump, daemon=True)
        pump.start()

        while proc.poll() is None:
            if stop.wait(0.5):
                _terminate_child(proc)
                pump.join(timeout=2)
                return
        pump.join(timeout=2)

        ran = time.time() - started
        rc = proc.returncode
        # FlowPilot exits 0 on SIGTERM/SIGINT/SIGQUIT (a clean stop); only a
        # non-zero code is a crash or a rejected configuration.
        if rc == 0:
            app.log.info("FlowPilot exited cleanly (code 0) after %.0fs", ran)
        else:
            app.log.warning("FlowPilot exited with code %s after %.0fs", rc, ran)
        delay = backoff
        if rc not in (0, None) and ran < 15 and error_lines:
            with lock:
                state["config_error"] = "\n".join(error_lines[-5:])
            delay = 30
        else:
            with lock:
                state["config_error"] = None
        if ran > 60:
            backoff = 1
        else:
            backoff = min(backoff * 2, 30)
        if stop.wait(delay):
            return


# ---------------------------------------------------------------------------
# Stats poller
# ---------------------------------------------------------------------------

def parse_time(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def update_exporters(stats, now):
    """Track per-exporter wall-clock activity. Returns {addr: fps}."""
    fps = {}
    with lock:
        for coll in stats.get("collectors") or []:
            cname = coll.get("name", "")
            for ex in coll.get("exporters") or []:
                addr = ex.get("address")
                if not addr:
                    continue
                fps[addr] = fps.get(addr, 0.0) + float(ex.get("flows_per_second") or 0)
                counter = int(ex.get("flows") or 0) + int(ex.get("datagrams") or 0)
                key = f"{cname}|{addr}"
                rec = exporters.get(key)
                if rec is None:
                    exporters[key] = {
                        "collector": cname, "address": addr, "counter": counter,
                        "last_seen": ex.get("last_seen"), "last_seen_wall": now,
                    }
                    continue
                if counter > rec["counter"]:
                    rec["last_seen_wall"] = now       # new traffic
                elif counter < rec["counter"]:
                    rec["last_seen_wall"] = now       # FlowPilot restarted: rebase, not silent
                rec["counter"] = counter
                rec["last_seen"] = ex.get("last_seen")
        for key in [k for k, r in exporters.items()
                    if now - r["last_seen_wall"] > EXPORTER_PRUNE_SECONDS]:
            del exporters[key]
        save_json(EXPORTERS_FILE, exporters)
    return fps


def fmt_minutes(seconds):
    return max(0, int(seconds // 60))


def evaluate(stats, now):
    """Compute conditions, fire/clear alerts, set the status line."""
    with lock:
        silent = []
        for rec in exporters.values():
            age = now - rec["last_seen_wall"]
            if age > SILENT_SECONDS:
                silent.append((age, rec))
        silent.sort(key=lambda x: -x[0])
        total_exp = len(exporters)

        no_flows = False
        no_flows_age = 0
        if collectors_enabled():
            ref = parse_time(stats.get("last_flow_at")) or parse_time(stats.get("started_at"))
            if ref is not None:
                no_flows_age = now - ref
                no_flows = no_flows_age > SILENT_SECONDS

        uploads = stats.get("uploads") or {}
        uploads_failing = stats.get("status") == "upload_failing"
        last_error = uploads.get("last_error") or "unknown error"

        conds = {
            "exporter_silent": (bool(silent), "warning"),
            "no_flows": (no_flows, "warning"),
            "uploads_failing": (uploads_failing, "critical"),
        }

        if silent:
            age, rec = silent[0]
            silent_title = f"Exporter {rec['address']} silent for {fmt_minutes(age)} min"
            silent_body = (f"{len(silent)} of {total_exp} exporters sent no flows for more than "
                           f"{SILENT_MINUTES} min. Longest silent: {rec['address']} "
                           f"({rec['collector']}), {fmt_minutes(age)} min.")
        else:
            silent_title = silent_body = ""
        titles = {
            "exporter_silent": (silent_title, silent_body),
            "no_flows": (f"No flows on any collector for {fmt_minutes(no_flows_age)} min",
                         f"No flows arrived on any enabled collector "
                         f"({', '.join(collectors_enabled())}) for more than {SILENT_MINUTES} min."),
            "uploads_failing": ("Uploads to the PCE are failing", f"Last error: {last_error}"),
        }

        changed = False
        for cond, (active, sev) in conds.items():
            was = bool(alert_state.get(cond))
            if active and not was:
                t, b = titles[cond]
                app.report(t, b, severity=sev, tags=["flowpilot", cond])
                alert_state[cond] = True
                changed = True
            elif was and not active:
                app.report(f"{cond} back to normal",
                           f"FlowPilot condition '{cond}' has cleared.",
                           severity="info", tags=["flowpilot", cond])
                alert_state[cond] = False
                changed = True
        if changed:
            save_json(ALERTS_FILE, alert_state)

        # Status line (same evaluation)
        if uploads_failing:
            line, level = f"✗ Uploads to the PCE failing — {last_error}", "crit"
        elif no_flows:
            line, level = f"⚠ No flows on any collector for {fmt_minutes(no_flows_age)}m", "warn"
        elif silent:
            age, rec = silent[0]
            sending = total_exp - len(silent)
            line = (f"⚠ {sending} of {total_exp} exporters sending · {len(silent)} silent "
                    f"for {fmt_minutes(age)}m ({rec['address']})")
            level = "warn"
        else:
            ok_ts = parse_time(uploads.get("last_success_at"))
            tail = (f"last upload accepted {fmt_minutes(now - ok_ts)}m ago"
                    if ok_ts else "no uploads yet")
            line, level = f"✓ Flows arriving · {tail}", "ok"
        state["status_line"] = line
        state["status_level"] = level


def poll_stats():
    last_hist = 0.0
    while not stop.is_set():
        now = time.time()
        try:
            r = requests.get(f"{STATS_URL}/stats", timeout=3)
            r.raise_for_status()
            stats = r.json()
        except Exception:
            with lock:
                state["stats_ok"] = False
                if state["status_level"] == "ok":
                    state["status_line"] = "⚠ FlowPilot stats unavailable"
                    state["status_level"] = "warn"
            stop.wait(POLL_SECONDS)
            continue
        try:
            with lock:
                state["stats"] = stats
                state["stats_ok"] = True
                state["last_poll"] = now
            fps = update_exporters(stats, now)
            if now - last_hist >= HISTORY_INTERVAL:
                last_hist = now
                point = {"t": int(now), "total_fps": round(sum(fps.values()), 2),
                         "per_exporter": {a: round(v, 2) for a, v in fps.items()}}
                with lock:
                    history.append(point)
                    del history[:-HISTORY_MAX]
                    save_json(HISTORY_FILE, history)
            evaluate(stats, now)
        except Exception:
            app.log.exception("Stats processing failed")
        stop.wait(POLL_SECONDS)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.api("GET", "/api/state")
def api_state(request):
    with lock:
        return {
            "stats": state["stats"],
            "status_line": state["status_line"],
            "status_level": state["status_level"],
            "config_error": state["config_error"],
            "flowpilot_running": child_running(),
            "host_ports_note": ("These are the container ports. Until plugger issue #43 "
                                "(fixed host ports), check `plugger status flowpilot` for the "
                                "mapped host port to point exporters at."),
            "collectors_enabled": collectors_enabled(),
            "container_ports": CONTAINER_PORTS,
            "silent_minutes": SILENT_MINUTES,
        }


@app.api("GET", "/api/history")
def api_history(request):
    with lock:
        return list(history)


@app.api("GET", "/api/health")
def api_health(request):
    with lock:
        cfg_err = state["config_error"]
    if cfg_err:
        return {"status": "unhealthy", "reason": cfg_err}, 503
    if not child_running():
        return {"status": "unhealthy", "reason": "flowpilot not running"}, 503
    try:
        r = requests.get(f"{STATS_URL}/healthz", timeout=2)
        try:
            body = r.json()
        except ValueError:
            body = {}
        if r.status_code == 200:
            return {"status": "healthy", "flowpilot": body}, 200
        if r.status_code == 503 and body.get("status") == "busy":
            return {"status": "healthy", "note": "flowpilot busy"}, 200
        if r.status_code == 503:
            return body or {"status": "unhealthy", "reason": "flowpilot unhealthy"}, 503
        return {"status": "unhealthy", "reason": f"flowpilot healthz returned {r.status_code}"}, 503
    except requests.RequestException:
        # Stats endpoint may still be starting; do not flap while the child is up.
        return {"status": "healthy", "note": "stats endpoint starting"}, 200


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FlowPilot</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config = { theme: { extend: { colors: { dark: { 900: '#11111b', 800: '#1e1e2e', 700: '#313244' } } } } };
</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<link rel="stylesheet" href="/brand/style.css" onerror="this.remove()">
</head>
<body class="bg-dark-900 text-gray-300 min-h-screen">
<div class="max-w-6xl mx-auto p-6 space-y-6">
  <h1 class="text-2xl font-bold text-white">FlowPilot <span class="text-sm font-normal text-gray-500">flow ingestion health</span></h1>

  <div id="config-error" class="hidden rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-red-300 text-sm">
    <div class="font-semibold mb-1">FlowPilot rejected its configuration</div>
    <pre id="config-error-text" class="whitespace-pre-wrap font-mono text-xs"></pre>
  </div>

  <div id="status" class="rounded-xl border p-5 text-xl font-semibold border-gray-700 bg-dark-800 text-gray-300">Loading...</div>

  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <div class="flex items-center justify-between mb-3">
      <div>
        <div class="text-xs uppercase text-gray-500">Flows per second (total now)</div>
        <div id="total-now" class="text-3xl font-bold text-white">-</div>
      </div>
      <div class="flex gap-2" id="range-buttons">
        <button data-min="15" class="range-btn px-3 py-1 rounded-lg text-sm bg-dark-700 text-gray-300">15m</button>
        <button data-min="60" class="range-btn px-3 py-1 rounded-lg text-sm bg-dark-700 text-gray-300">1h</button>
        <button data-min="1440" class="range-btn px-3 py-1 rounded-lg text-sm bg-dark-700 text-gray-300">24h</button>
      </div>
    </div>
    <div style="height:260px"><canvas id="chart"></canvas></div>
  </div>

  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5 overflow-x-auto">
    <h2 class="text-white font-semibold mb-3">Exporters</h2>
    <table class="w-full text-sm">
      <thead class="text-left text-xs uppercase text-gray-500">
        <tr><th class="py-1 pr-3"></th><th class="pr-3">Address</th><th class="pr-3">Protocol</th><th class="pr-3">Last flow</th>
        <th class="pr-3">Flows/s</th><th class="pr-3">Templates</th><th>Decode errors</th></tr>
      </thead>
      <tbody id="exporter-rows"></tbody>
    </table>
    <div id="exporter-empty" class="hidden text-gray-500 text-sm py-3">No exporters have sent data yet.</div>
  </div>

  <div class="grid md:grid-cols-3 gap-4">
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <h2 class="text-white font-semibold mb-2">Uploads to the PCE</h2>
      <div id="panel-uploads" class="text-sm space-y-1"></div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <h2 class="text-white font-semibold mb-2">Unmanaged workloads</h2>
      <div id="panel-unmanaged" class="text-sm space-y-1"></div>
    </div>
    <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
      <h2 class="text-white font-semibold mb-2">Ingestion</h2>
      <div id="panel-ingestion" class="text-sm space-y-1"></div>
    </div>
  </div>

  <div class="bg-dark-800 rounded-xl border border-gray-700 p-5">
    <h2 class="text-white font-semibold mb-2">UDP ports</h2>
    <ul id="ports" class="text-sm space-y-1"></ul>
    <p id="ports-note" class="text-xs text-gray-500 mt-3"></p>
  </div>
</div>

<script>
var rangeMin = 60;
var chart = null;
var historyData = [];
var lastState = null;
var PALETTE = ['#89b4fa', '#a6e3a1', '#f9e2af', '#fab387', '#cba6f7', '#94e2d5', '#f38ba8', '#74c7ec'];

function esc(s) {
  return String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, function (c) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
  });
}
function parseT(s) { if (!s) return null; var t = Date.parse(s); return isNaN(t) ? null : t / 1000; }
function ago(s) {
  var t = parseT(s);
  if (t === null) return 'never';
  var d = Math.max(0, Math.round(Date.now() / 1000 - t));
  if (d < 60) return d + 's ago';
  if (d < 3600) return Math.floor(d / 60) + 'm ago';
  if (d < 86400) return Math.floor(d / 3600) + 'h ago';
  return Math.floor(d / 86400) + 'd ago';
}
function num(v) { return (v === null || v === undefined) ? 0 : Number(v); }
function fmtN(v) { return Number(v).toLocaleString(); }
function row(label, value) {
  return '<div class="flex justify-between gap-3"><span class="text-gray-500">' + esc(label) +
         '</span><span class="text-gray-200 text-right">' + value + '</span></div>';
}

function renderStatus(st) {
  var el = document.getElementById('status');
  var cls = {
    ok: 'border-green-500/40 bg-green-500/10 text-green-300',
    warn: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
    crit: 'border-red-500/40 bg-red-500/10 text-red-300'
  }[st.status_level] || 'border-gray-700 bg-dark-800 text-gray-300';
  el.className = 'rounded-xl border p-5 text-xl font-semibold ' + cls;
  el.textContent = st.status_line || '';
  var ce = document.getElementById('config-error');
  if (st.config_error) {
    ce.classList.remove('hidden');
    document.getElementById('config-error-text').textContent = st.config_error;
  } else {
    ce.classList.add('hidden');
  }
}

function lastHistoryFps(addr) {
  if (historyData.length < 2) return null;
  var p = historyData[historyData.length - 2];
  if (p && p.per_exporter && addr in p.per_exporter) return p.per_exporter[addr];
  return null;
}

function renderExporters(st) {
  var stats = st.stats;
  var body = document.getElementById('exporter-rows');
  var silentSec = num(st.silent_minutes) * 60;
  var html = '';
  var count = 0;
  var colls = (stats && stats.collectors) || [];
  colls.forEach(function (c) {
    (c.exporters || []).forEach(function (ex) {
      count++;
      var t = parseT(ex.last_seen);
      var age = t === null ? null : Date.now() / 1000 - t;
      var color = 'bg-green-400';
      if (age === null || age > silentSec) color = 'bg-red-400';
      else if (num(ex.waiting_for_template) > 0) color = 'bg-amber-400';
      var fps = num(ex.flows_per_second);
      var prev = lastHistoryFps(ex.address);
      var trend = '';
      if (prev !== null) {
        if (fps > prev) trend = ' <span class="text-green-400 text-xs">▲</span>';
        else if (fps < prev) trend = ' <span class="text-red-400 text-xs">▼</span>';
      }
      html += '<tr class="border-t border-gray-700">' +
        '<td class="py-2 pr-3"><span class="inline-block w-2.5 h-2.5 rounded-full ' + color + '"></span></td>' +
        '<td class="pr-3 font-mono text-gray-200">' + esc(ex.address) + '</td>' +
        '<td class="pr-3">' + esc((ex.protocols || []).join(', ')) + '</td>' +
        '<td class="pr-3">' + esc(ago(ex.last_seen)) + '</td>' +
        '<td class="pr-3">' + fps.toFixed(1) + trend + '</td>' +
        '<td class="pr-3">' + fmtN(num(ex.templates)) + '</td>' +
        '<td>' + fmtN(num(ex.decode_errors)) + '</td></tr>';
    });
  });
  colls.forEach(function (c) {
    var rej = num(c.rejected_datagrams);
    if (rej > 0) {
      html += '<tr class="border-t border-gray-700 text-gray-400"><td class="py-2 pr-3">' +
        '<span class="inline-block w-2.5 h-2.5 rounded-full bg-amber-400"></span></td>' +
        '<td colspan="6">' + esc(c.name) + ': ' + fmtN(rej) +
        ' datagrams dropped from senders not in the allow-list</td></tr>';
    }
  });
  body.innerHTML = html;
  document.getElementById('exporter-empty').classList.toggle('hidden', count > 0 || html !== '');
}

function renderPanels(st) {
  var stats = st.stats || {};
  var up = stats.uploads;
  var u = '';
  if (up) {
    var failing = stats.status === 'upload_failing';
    u += row('Last success', esc(up.last_success_at ? ago(up.last_success_at) : 'none yet'));
    u += row('Queued', fmtN(num(up.queued_files)) + ' files / ' + fmtN(num(up.queued_bytes)) + ' B');
    u += row('Failing', failing ? '<span class="text-red-400">yes</span>' : '<span class="text-green-400">no</span>');
    if (up.last_error) u += row('Last error', esc(up.last_error));
  } else { u = '<span class="text-gray-500">no data</span>'; }
  document.getElementById('panel-uploads').innerHTML = u;

  var um = stats.unmanaged_workloads;
  var h = '';
  if (um) {
    h += row('Mode', um.dry_run ? '<span class="px-2 rounded bg-blue-500/15 text-blue-300 text-xs">dry run</span>' : 'live');
    h += row('Created today', fmtN(num(um.created_today)) + ' / ' + fmtN(num(um.daily_cap)));
    h += row('Waiting (eligible)', fmtN(num(um.last_window && um.last_window.eligible)));
    if (um.disabled_reason) h += row('Disabled', esc(um.disabled_reason));
  } else { h = '<span class="text-gray-500">off</span>'; }
  document.getElementById('panel-unmanaged').innerHTML = h;

  var total = 0, decoded = 0, dropped = 0;
  (stats.collectors || []).forEach(function (c) {
    (c.exporters || []).forEach(function (ex) { total += num(ex.flows_per_second); });
    decoded += num(c.flows_decoded);
    var fd = c.flows_dropped || {};
    Object.keys(fd).forEach(function (k) { dropped += num(fd[k]); });
  });
  var share = decoded > 0 ? (dropped / decoded * 100).toFixed(1) + '%' : '-';
  var g = row('Flows/s', total.toFixed(1)) + row('Dropped share', share) +
          row('Flows decoded', fmtN(decoded));
  document.getElementById('panel-ingestion').innerHTML = g;
  document.getElementById('total-now').textContent = total.toFixed(1);
}

function renderPorts(st) {
  var ports = st.container_ports || {};
  var en = st.collectors_enabled || [];
  var html = '';
  Object.keys(ports).forEach(function (n) {
    var on = en.indexOf(n) >= 0;
    html += '<li><span class="font-mono text-gray-200">' + esc(n) + '</span> UDP ' + esc(ports[n]) +
      ' <span class="text-xs ' + (on ? 'text-green-400' : 'text-gray-500') + '">' +
      (on ? 'enabled' : 'disabled') + '</span></li>';
  });
  document.getElementById('ports').innerHTML = html;
  document.getElementById('ports-note').textContent = st.host_ports_note || '';
}

function renderChart() {
  var cutoff = Date.now() / 1000 - rangeMin * 60;
  var pts = historyData.filter(function (p) { return p.t >= cutoff; });
  var labels = pts.map(function (p) { return new Date(p.t * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', hour12: false}); });
  var addrs = {};
  pts.forEach(function (p) { Object.keys(p.per_exporter || {}).forEach(function (a) { addrs[a] = true; }); });
  var datasets = [{label: 'total', data: pts.map(function (p) { return p.total_fps; }),
                   borderColor: '#cdd6f4', backgroundColor: 'transparent', borderWidth: 2, tension: 0.2, pointRadius: 0}];
  Object.keys(addrs).forEach(function (a, i) {
    datasets.push({label: a, data: pts.map(function (p) { return (p.per_exporter || {})[a] || 0; }),
                   borderColor: PALETTE[i % PALETTE.length], backgroundColor: 'transparent',
                   borderWidth: 1.5, tension: 0.2, pointRadius: 0});
  });
  if (typeof Chart === 'undefined') return;
  if (!chart) {
    chart = new Chart(document.getElementById('chart'), {
      type: 'line', data: {labels: labels, datasets: datasets},
      options: {responsive: true, maintainAspectRatio: false, animation: false,
        plugins: {legend: {labels: {color: '#a6adc8'}}},
        scales: {x: {ticks: {color: '#6c7086', maxTicksLimit: 8}, grid: {color: '#313244'}},
                 y: {beginAtZero: true, ticks: {color: '#6c7086'}, grid: {color: '#313244'}}}}
    });
  } else {
    chart.data.labels = labels;
    chart.data.datasets = datasets;
    chart.update();
  }
}

function setRange(min) {
  rangeMin = min;
  document.querySelectorAll('.range-btn').forEach(function (b) {
    var active = Number(b.getAttribute('data-min')) === min;
    b.className = 'range-btn px-3 py-1 rounded-lg text-sm ' +
      (active ? 'bg-[rgba(137,180,250,0.2)] text-[#89b4fa]' : 'bg-dark-700 text-gray-300');
  });
  renderChart();
}

function loadHistory() {
  return fetch('api/history').then(function (r) { return r.json(); }).then(function (h) {
    historyData = Array.isArray(h) ? h : [];
    renderChart();
  }).catch(function () {});
}

function refresh() {
  fetch('api/state').then(function (r) { return r.json(); }).then(function (st) {
    lastState = st;
    renderStatus(st);
    renderExporters(st);
    renderPanels(st);
    renderPorts(st);
  }).catch(function () {
    var el = document.getElementById('status');
    el.className = 'rounded-xl border p-5 text-xl font-semibold border-amber-500/40 bg-amber-500/10 text-amber-300';
    el.textContent = '⚠ Dashboard cannot reach the plugin';
  });
}

document.querySelectorAll('.range-btn').forEach(function (b) {
  b.addEventListener('click', function () { setRange(Number(b.getAttribute('data-min'))); });
});
setRange(60);
refresh();
loadHistory();
setInterval(refresh, 5000);
setInterval(loadHistory, 60000);
</script>
</body>
</html>
"""


@app.dashboard
def dashboard():
    return DASHBOARD_HTML


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.makedirs(PLUGIN_DIR, exist_ok=True)
    os.makedirs(os.path.join(DATA_DIR, "flowpilot"), exist_ok=True)

    os.environ.update(build_flowpilot_env())

    with lock:
        h = load_json(HISTORY_FILE, [])
        if isinstance(h, list):
            history.extend(h[-HISTORY_MAX:])
        a = load_json(ALERTS_FILE, {})
        if isinstance(a, dict):
            alert_state.update(a)
        ex = load_json(EXPORTERS_FILE, {})
        if isinstance(ex, dict):
            # Silence is measured while we are watching: rebase to plugin start.
            for rec in ex.values():
                rec["last_seen_wall"] = max(float(rec.get("last_seen_wall", 0)), START_TIME)
            exporters.update(ex)

    sup = threading.Thread(target=supervise, name="supervisor", daemon=True)
    sup.start()
    threading.Thread(target=poll_stats, name="stats-poller", daemon=True).start()

    try:
        # The SDK installs its own SIGTERM/SIGINT handlers that stop the HTTP
        # server; app.run() then returns and we stop the child cleanly below.
        app.run(port=8080)
    finally:
        stop.set()
        sup.join(timeout=15)
        with _proc_lock:
            _terminate_child(_proc)


if __name__ == "__main__":
    main()
