"""
Plugger Python SDK — eliminates boilerplate for Illumio PCE plugins.

Usage:
    from plugger_sdk import Plugin

    app = Plugin("my-plugin")

    @app.poll(interval_env="POLL_INTERVAL", default=3600)
    def work(pce):
        app.state["data"] = pce.get("/workloads").json()

    @app.api("GET", "/api/data")
    def get_data(request):
        return app.state

    app.run()

Env vars injected by plugger:
    PCE_HOST, PCE_PORT, PCE_ORG_ID, PCE_API_KEY, PCE_API_SECRET
    PLUGGER_PLUGIN_NAME, PLUGGER_URL, PLUGGER_WEBHOOK_TOKEN
"""

import json
import logging
import os
import re
import signal
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ---------------------------------------------------------------------------
# Dark/light theme (shared across every plugin dashboard)
# ---------------------------------------------------------------------------
#
# Spliced in right after <head> of any full-HTML dashboard response. It mirrors
# the plugger management shell (internal/dashboard/templates/layout.html): the
# same localStorage key ('plugger-theme'), the same 3-state light/auto/dark
# semantics (absent => dark, to match the shell), and the same html:not(.dark)
# override tokens. Plugin pages render same-origin under /plugins/{name}/ui/, so
# the shell's toggle and the plugin page share one theme preference for free.
#
# The toggle is a self-contained floating control (no Tailwind/framework
# dependency) and all logic lives inside one IIFE, so it never collides with a
# plugin's own globals. Light-mode *appearance* is best-effort: it remaps the
# standard Catppuccin utility classes; a plugin that hardcodes hex in inline
# styles keeps the toggle but may need per-plugin tuning later.
_THEME_SNIPPET = r"""<style data-plugger-theme>
html:not(.dark) body { background:#f9fafb; color:#1f2937; }
html:not(.dark) .bg-dark-900 { background:#f9fafb; }
html:not(.dark) .bg-dark-800 { background:#ffffff; border-color:#e5e7eb; }
html:not(.dark) .bg-dark-700 { background:#f3f4f6; }
html:not(.dark) .bg-dark-700\/50, html:not(.dark) .bg-dark-700\/30, html:not(.dark) .bg-dark-700\/20 { background:#f3f4f680; }
html:not(.dark) .border-gray-700 { border-color:#e5e7eb; }
html:not(.dark) .border-gray-700\/50, html:not(.dark) .border-gray-700\/30 { border-color:#e5e7eb80; }
html:not(.dark) .text-gray-200 { color:#1f2937; }
html:not(.dark) .text-gray-300 { color:#374151; }
html:not(.dark) .text-gray-400 { color:#6b7280; }
html:not(.dark) .text-gray-500 { color:#9ca3af; }
html:not(.dark) .text-white { color:#111827; }
html:not(.dark) code { background:#e5e7eb; color:#374151; }
#plugger-theme-toggle { position:fixed; top:12px; right:12px; z-index:2147483000;
  display:flex; gap:2px; padding:3px; border-radius:9999px;
  background:rgba(49,50,68,0.85); border:1px solid rgba(255,255,255,0.08);
  box-shadow:0 2px 8px rgba(0,0,0,0.3); -webkit-backdrop-filter:blur(6px); backdrop-filter:blur(6px);
  font-family:system-ui,-apple-system,sans-serif; line-height:1; }
html:not(.dark) #plugger-theme-toggle { background:rgba(255,255,255,0.9); border-color:#e5e7eb; box-shadow:0 2px 8px rgba(0,0,0,0.12); }
#plugger-theme-toggle button { all:unset; cursor:pointer; width:26px; height:26px;
  display:flex; align-items:center; justify-content:center; border-radius:9999px;
  font-size:14px; color:#9399b2; transition:background .15s, color .15s; }
#plugger-theme-toggle button:hover { color:#cdd6f4; }
html:not(.dark) #plugger-theme-toggle button { color:#6b7280; }
html:not(.dark) #plugger-theme-toggle button:hover { color:#111827; }
#plugger-theme-toggle button[aria-pressed="true"] { background:#89b4fa; color:#11111b; }
</style>
<script data-plugger-theme>
(function(){
  var KEY='plugger-theme', ORDER=['light','auto','dark'];
  function systemDark(){ return window.matchMedia('(prefers-color-scheme: dark)').matches; }
  function read(){ try { return localStorage.getItem(KEY); } catch(e){ return null; } }
  function resolve(mode){ return mode==='dark' ? true : mode==='light' ? false : systemDark(); }
  function current(){ var s=read(); return (s==='light'||s==='auto'||s==='dark') ? s : 'dark'; }
  // Initial paint (synchronous, before body renders) — absent preference => dark, like the shell.
  document.documentElement.classList.toggle('dark', resolve(current()));
  function updateButtons(mode){
    var wrap=document.getElementById('plugger-theme-toggle'); if(!wrap) return;
    var btns=wrap.querySelectorAll('button');
    for(var i=0;i<btns.length;i++){ btns[i].setAttribute('aria-pressed', String(ORDER[i]===mode)); }
  }
  function setTheme(mode){
    try { localStorage.setItem(KEY, mode); } catch(e){}
    document.documentElement.classList.toggle('dark', resolve(mode));
    updateButtons(mode);
  }
  function build(){
    if(document.getElementById('plugger-theme-toggle') || !document.body) return;
    var cur=current(), wrap=document.createElement('div'); wrap.id='plugger-theme-toggle';
    var glyph={light:'☀', auto:'◐', dark:'☾'}, name={light:'Light', auto:'System', dark:'Dark'};
    ORDER.forEach(function(m){
      var b=document.createElement('button');
      b.textContent=glyph[m]; b.title=name[m]+' mode'; b.setAttribute('aria-label', name[m]+' mode');
      b.setAttribute('aria-pressed', String(m===cur));
      b.addEventListener('click', function(){ setTheme(m); });
      wrap.appendChild(b);
    });
    document.body.appendChild(wrap);
  }
  if(document.readyState==='loading') document.addEventListener('DOMContentLoaded', build); else build();
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(){
    var s=read(); if(s==='auto' || !s){ document.documentElement.classList.toggle('dark', systemDark()); }
  });
})();
</script>
"""


def _inject_theme(html):
    """Splice the theme snippet in after <head>. Returns html unchanged when it
    is not a full HTML document or the snippet is already present."""
    if not isinstance(html, str) or "data-plugger-theme" in html:
        return html
    m = re.search(r"<head[^>]*>", html, re.IGNORECASE)
    if not m:
        return html
    return html[:m.end()] + "\n" + _THEME_SNIPPET + html[m.end():]


# ---------------------------------------------------------------------------
# Request wrapper
# ---------------------------------------------------------------------------

class Request:
    __slots__ = ("method", "path", "query", "body", "_json")

    def __init__(self, method, path, query, body):
        self.method = method
        self.path = path
        self.query = query
        self.body = body
        self._json = None

    @property
    def json(self):
        if self._json is None:
            try:
                self._json = json.loads(self.body) if self.body else {}
            except (json.JSONDecodeError, TypeError):
                self._json = {}
        return self._json


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class Plugin:
    def __init__(self, name, inject_theme=True):
        self.name = name
        self._inject_theme = inject_theme
        self._log = None
        self._pce = None
        self._labels = None
        self._label_href_map = None
        self._state = {}
        self._lock = threading.Lock()
        self._poll_fn = None
        self._poll_interval = 3600
        self._routes = {}
        self._dashboard_fn = None
        self._poll_event = threading.Event()
        self._setup_logging()

    # -- Logging --

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        self._log = logging.getLogger(self.name)

    @property
    def log(self):
        return self._log

    # -- Environment --

    def env(self, name, default=""):
        return os.environ.get(name, default)

    # -- PCE --

    @property
    def pce(self):
        if self._pce is None:
            from illumio import PolicyComputeEngine
            pce = PolicyComputeEngine(
                url=os.environ["PCE_HOST"],
                port=os.environ.get("PCE_PORT", "8443"),
                org_id=os.environ.get("PCE_ORG_ID", "1"),
            )
            pce.set_credentials(
                username=os.environ["PCE_API_KEY"],
                password=os.environ["PCE_API_SECRET"],
            )
            verify = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() != "true"
            pce.set_tls_settings(verify=verify)
            self._pce = pce
            self._log.info("Connected to PCE: %s", pce.base_url)
        return self._pce

    # -- Labels --

    @property
    def labels(self):
        if self._labels is None:
            self._fetch_labels()
        return self._labels

    def _fetch_labels(self):
        self._labels = {}
        self._label_href_map = {}
        try:
            resp = self.pce.get("/labels")
            if resp.status_code == 200:
                for lbl in resp.json():
                    href = lbl.get("href", "")
                    key = lbl.get("key", "")
                    value = lbl.get("value", "")
                    if href:
                        self._labels[href] = {"key": key, "value": value}
                        self._label_href_map[(key, value)] = href
                self._log.info("Loaded %d labels", len(self._labels))
        except Exception as e:
            self._log.warning("Failed to fetch labels: %s", e)

    def resolve_label(self, href):
        labels = self.labels
        if href in labels:
            c = labels[href]
            return c["key"], c["value"]
        return None, None

    def resolve_workload_labels(self, workload):
        result = {}
        for lbl in workload.get("labels", []):
            if isinstance(lbl, dict):
                href = lbl.get("href", "")
                if href:
                    key, val = self.resolve_label(href)
                    if key:
                        result[key] = val
                elif lbl.get("key") and lbl.get("value"):
                    result[lbl["key"]] = lbl["value"]
        return result

    def ensure_label(self, key, value):
        if self._label_href_map is None:
            self._fetch_labels()
        existing = self._label_href_map.get((key, value))
        if existing:
            return existing
        try:
            resp = self.pce.post("/labels", json={"key": key, "value": value})
            if resp.status_code in (200, 201):
                href = resp.json().get("href", "")
                if href:
                    self._label_href_map[(key, value)] = href
                    self._labels[href] = {"key": key, "value": value}
                return href
        except Exception as e:
            self._log.warning("Failed to create label %s:%s — %s", key, value, e)
        return ""

    def pce_link(self, href):
        pce_host = os.environ.get("PCE_HOST", "localhost")
        m = re.match(r'.*/orgs/\d+/(.*)', href)
        path = m.group(1) if m else href.lstrip('/')
        path = path.replace('sec_policy/draft/', '').replace('sec_policy/active/', '')
        return f"https://{pce_host}/#/{path}"

    # -- State --

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        with self._lock:
            self._state = value

    def update_state(self, updates):
        with self._lock:
            self._state.update(updates)

    # -- Reporting --

    def report(self, title, body="", severity="info", tags=None, data=None):
        plugger_url = os.environ.get("PLUGGER_URL", "")
        if not plugger_url:
            return
        token = os.environ.get("PLUGGER_WEBHOOK_TOKEN", "")
        plugin_name = os.environ.get("PLUGGER_PLUGIN_NAME", self.name)

        def _send():
            try:
                import requests as req_lib
                req_lib.post(
                    f"{plugger_url}/api/reports/publish",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "plugin": plugin_name,
                        "title": title,
                        "severity": severity,
                        "body": body,
                        "tags": tags or [],
                        "data": data or {},
                    },
                    timeout=5,
                )
            except Exception:
                pass

        threading.Thread(target=_send, daemon=True).start()

    # -- Decorators --

    def poll(self, interval_env="POLL_INTERVAL", default=3600):
        def decorator(fn):
            self._poll_fn = fn
            self._poll_interval = max(1, int(os.environ.get(interval_env, str(default))))
            return fn
        return decorator

    def api(self, method, path):
        def decorator(fn):
            key = f"{method.upper()} {path}"
            self._routes[key] = fn
            return fn
        return decorator

    def dashboard(self, fn):
        self._dashboard_fn = fn
        return fn

    # -- Poll control --

    def trigger_poll(self):
        self._poll_event.set()

    # -- Run --

    def run(self, port=None):
        if port is None:
            port = int(os.environ.get("HTTP_PORT", "8080"))

        self._log.info("Starting %s...", self.name)

        # Register built-in routes
        plugin = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._handle("GET")

            def do_POST(self):
                self._handle("POST")

            def do_PUT(self):
                self._handle("PUT")

            def do_DELETE(self):
                self._handle("DELETE")

            def do_OPTIONS(self):
                self._send(200, "")

            def _handle(self, method):
                parsed = urlparse(self.path)
                path = parsed.path.rstrip("/") or "/"
                query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}

                # Built-in: healthz
                if path == "/healthz":
                    self._send_json(200, {
                        "status": "healthy",
                        "plugin": plugin.name,
                        "state_keys": list(plugin._state.keys()),
                    })
                    return

                # Built-in: dashboard
                if path == "/" and method == "GET":
                    if plugin._dashboard_fn:
                        html = plugin._dashboard_fn()
                        if plugin._inject_theme:
                            html = _inject_theme(html)
                        self._send(200, html, "text/html; charset=utf-8")
                    else:
                        self._send_json(200, plugin._state)
                    return

                # User-defined routes
                key = f"{method} {path}"
                handler = plugin._routes.get(key)
                if handler is None:
                    self._send(404, json.dumps({"error": "Not found"}))
                    return

                body = b""
                content_length = int(self.headers.get("Content-Length", 0))
                if content_length > 0:
                    body = self.rfile.read(content_length)

                req = Request(method, path, query, body)
                try:
                    result = handler(req)
                    if isinstance(result, tuple):
                        data, code = result
                    else:
                        data, code = result, 200

                    if isinstance(data, dict) or isinstance(data, list):
                        self._send_json(code, data)
                    elif isinstance(data, str):
                        self._send(code, data, "text/html; charset=utf-8")
                    else:
                        self._send_json(code, data)
                except Exception as e:
                    plugin._log.exception("API error: %s %s", method, path)
                    self._send_json(500, {"error": str(e)})

            def _send_json(self, code, data):
                body = json.dumps(data, indent=2, default=str).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.end_headers()
                self.wfile.write(body)

            def _send(self, code, body, content_type="application/json"):
                if isinstance(body, str):
                    body = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        # Poller thread (initial poll + recurring)
        if self._poll_fn:
            def _poller():
                try:
                    self._poll_fn(self.pce)
                except Exception:
                    self._log.exception("Initial poll failed")
                while True:
                    self._poll_event.wait(timeout=self._poll_interval)
                    self._poll_event.clear()
                    try:
                        self._fetch_labels()
                        self._poll_fn(self.pce)
                    except Exception:
                        self._log.exception("Poll cycle failed")

            threading.Thread(target=_poller, daemon=True).start()

        # HTTP server
        server = HTTPServer(("0.0.0.0", port), Handler)
        self._log.info("Dashboard on http://0.0.0.0:%d", port)

        def shutdown(signum, frame):
            self._log.info("Shutting down...")
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        server.serve_forever()
        self._log.info("%s stopped.", self.name)
