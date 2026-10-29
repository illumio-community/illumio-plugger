#!/usr/bin/env python3
"""
mock-hec — a tiny stand-in for Splunk's HTTP Event Collector (HEC).

Run it, point a plugger `splunk` output at http://localhost:8088, and every
report plugger delivers is validated and pretty-printed to your terminal.
No Splunk, no license, no dependencies (Python stdlib only).

Usage:
    python3 mock_hec.py                    # listen on :8088, accept any token
    PORT=9000 python3 mock_hec.py          # custom port
    HEC_TOKEN=secret python3 mock_hec.py   # require this exact HEC token

Then, in plugger's environment:
    plugger output add mock --type splunk \\
        --hec-url http://localhost:8088 --hec-token-env HEC_TOKEN \\
        --plugins pce-expiry-watch
    export HEC_TOKEN=secret        # must match the mock if you set HEC_TOKEN
    plugger reload
    plugger output test mock       # fires a test event at the mock
"""

import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8088"))
EXPECTED_TOKEN = os.environ.get("HEC_TOKEN", "")

GREEN, RED, YELLOW, DIM, BOLD, RST = (
    "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[1m", "\033[0m",
)


def _events(body):
    """Yield JSON objects from a HEC body (newline-delimited or concatenated)."""
    dec = json.JSONDecoder()
    s = body.strip()
    i = 0
    while i < len(s):
        while i < len(s) and s[i].isspace():
            i += 1
        if i >= len(s):
            break
        obj, end = dec.raw_decode(s, i)
        yield obj
        i = end


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # replaced by our own logging

    def _reply(self, code, text, num):
        payload = json.dumps({"text": text, "code": num}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.startswith("/services/collector/health"):
            self._reply(200, "HEC is available and accepting input", 17)
        else:
            self._reply(404, "Not found", 404)

    def do_POST(self):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Splunk "):
            print(f"{RED}[{ts}] 401 missing 'Authorization: Splunk <token>'{RST} path={self.path}")
            self._reply(401, "Token is required", 2)
            return
        token = auth[len("Splunk "):]
        if EXPECTED_TOKEN and token != EXPECTED_TOKEN:
            print(f"{RED}[{ts}] 403 invalid token{RST} path={self.path}")
            self._reply(403, "Invalid token", 4)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        try:
            events = list(_events(body))
        except json.JSONDecodeError as e:
            print(f"{RED}[{ts}] 400 body is not valid HEC JSON: {e}{RST}\n{body}")
            self._reply(400, "Invalid data format", 6)
            return

        print(f"{GREEN}[{ts}] {BOLD}{len(events)} event(s){RST}{GREEN} on {self.path}{RST} "
              f"{DIM}(token {token[:4]}…, {length} bytes){RST}")
        for ev in events:
            idx = ev.get("index", "-")
            st = ev.get("sourcetype", "-")
            inner = ev.get("event", ev)
            sev = inner.get("severity", "") if isinstance(inner, dict) else ""
            sevtag = {"critical": RED, "warning": YELLOW}.get(sev, "")
            head = f"  → index={idx} sourcetype={st}"
            if sevtag:
                head += f" severity={sevtag}{sev}{RST}"
            print(head)
            print(DIM + json.dumps(inner, indent=2) + RST)

        self._reply(200, "Success", 0)


def main():
    # Line-buffer stdout so events print live even when piped/redirected.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    tok = f"require token {EXPECTED_TOKEN!r}" if EXPECTED_TOKEN else "accept any token"
    print(f"{BOLD}mock-hec{RST} listening on http://0.0.0.0:{PORT}  ({tok})")
    print(f"{DIM}POST events to /services/collector/event — Ctrl-C to stop{RST}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
