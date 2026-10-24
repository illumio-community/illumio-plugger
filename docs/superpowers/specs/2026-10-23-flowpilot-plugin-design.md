# FlowPilot plugin: design

Date: 2026-10-23. Status: draft for review.

## Intent

An Illumio admin who runs plugger wants to collect network flows (NetFlow, IPFIX, sFlow, syslog-style text) from
routers and firewalls and send them to the PCE without installing FlowLink, and wants to see at a glance that each
exporter's flows are actually arriving. The failure that matters most: **exporters stop sending and nobody
notices.** Everything in the design serves "flows are arriving, and you'll hear about it when they stop".

FlowPilot is a standalone flow collector ([github.com/alexgoller/flowpilot](https://github.com/alexgoller/flowpilot), Apache-2.0, a Rust reimplementation of FlowLink). It
already does all the collecting, aggregation, PCE upload and unmanaged workload creation, takes its whole
configuration from `FLOWPILOT_*` environment variables, picks up plugger's `PCE_*` credentials, and exposes
`/healthz`, `/stats` (JSON) and `/metrics` (Prometheus) on an optional local HTTP endpoint. Field reference: the
FlowPilot repo's `docs/stats.md`; variable reference: its `docs/configuration.md`.

## Goals

- A plugger plugin, `flowpilot`, that runs FlowPilot and shows a dashboard of flow ingestion.
- Configuration through plugger's settings form only; no config file for the admin to write.
- Alerts through plugger notifications when exporters go silent, no flows arrive, or uploads fail.

## Non-goals

- **No change to FlowPilot.** The plugin uses the binary as it is. FlowPilot stays a standalone product that must
  remain fully usable without plugger; the plugin is only one way to run it.
- No change to plugger in this project. The fixed host port it needs is plugger issue
  [#43](https://github.com/illumio-community/illumio-plugger/issues/43), built separately in plugger.
- No flow analytics (top talkers, traffic maps). The PCE does that; this page is about ingestion health.

## Anti-goals

- An exporter that went silent shown only as a red dot nobody looks at.
- A dashboard that says "all good" while uploads to the PCE fail.
- Restarting FlowPilot because a router stopped sending (it can't help, and loses in-memory state).

## Shape

One image, built like the other Python plugins (`traffic-reporter` is the closest example):

- **The FlowPilot binary**, unchanged.
- **A Python process** built on `plugin-templates/plugger_sdk.py`. It:
  - maps plugger settings to `FLOWPILOT_*` variables and starts FlowPilot as a child process, with
    `FLOWPILOT_STATS_HTTP_LISTEN=127.0.0.1:<port>` so the stats endpoint is reachable only inside the container;
  - restarts FlowPilot if it exits, with a backoff, and stops it cleanly (SIGTERM, then wait) on shutdown;
  - passes FlowPilot's log through to its own stdout, so `plugger logs flowpilot` shows FlowPilot's log, including the
    `FLOWPILOT_STATS` lines;
  - polls `/stats` every few seconds, keeps the history for the chart, evaluates alerts;
  - serves the dashboard and its own `/healthz` on the `ui` port, which plugger proxies at `/plugins/flowpilot/ui/`.
- **A volume** for FlowPilot's data directory (queued uploads, unmanaged workload state) and the chart history, so
  both survive restarts.

### Ports (`.plugger/metadata.yaml`)

- `ui` (TCP, 8080): dashboard.
- One UDP port per collector: NetFlow 2055, IPFIX 4739, sFlow 6343, text 514. Declared with a fixed host port once
  issue #43 exists. Until then they get plugger's random host port; the dashboard shows the actual host port so a
  test setup still works.

### Health

Plugger's health check calls the Python `/healthz`. Healthy means: the Python process is serving, FlowPilot is running,
and FlowPilot's own `/healthz` answers 200. FlowPilot's `/healthz` returns 503 only when a restart can help (a core
thread died); a busy-endpoint 503 (`{"status":"busy"}`) is retried, not treated as unhealthy. A silent exporter or a
failing upload never makes the plugin unhealthy; those raise alerts instead.

## Settings form (`metadata.config[]` → `FLOWPILOT_*`)

PCE address, org and API credentials come from plugger (`PCE_*`); FlowPilot picks them up itself.

| Group | Settings |
|---|---|
| Collectors | NetFlow, IPFIX, sFlow, text: each on/off and port (defaults 2055, 4739, 6343, 514; NetFlow on, others off). Optional allowed exporter addresses per collector. |
| Text parser | Field for source IP, destination IP, destination port, protocol (required when text is on); optional bytes, ICMP type, ICMP code, timestamp; timestamp format; "line must contain" filter; field separator; attribute separator. |
| Basics | Aggregation window in minutes (default 10), verify the PCE certificate (default on). |
| Unmanaged workloads | On/off, dry run, internal networks, flow threshold, per-window and per-day caps, label rules per network. |
| Alerts | Silent-exporter time in minutes (default 15). |

Left out of the form on purpose: proxy settings, data directory limits, file retention, max flows per post. An
advanced user can still set any `FLOWPILOT_*` variable directly. FlowPilot validates the configuration at start; when
it rejects a setting, its error (which names the variable) is shown on the dashboard, not only in the log.

## Dashboard

Layout agreed from mockups (layout "A with the chart"), top to bottom:

1. **Status line** answering the question: e.g. "✓ Flows arriving · last upload accepted 3 min ago" or
   "⚠ 2 of 3 exporters sending · 1 silent for 14 min (10.2.0.9)". Same state the alerts use.
2. **Flows per second chart**: total now, range 15 min / 1 h / 24 h, one line per exporter, so a silent exporter
   shows as its line dropping to zero. History sampled by the Python process and kept in the volume.
3. **Exporter table**: status dot, exporter address, protocol, last flow ("2 s ago"), flows/s with a small trend,
   templates known, decode errors. Rejected senders (not in the allowed list) appear as their own rows with the
   number of dropped datagrams. "Waiting for template" shows as a yellow state.
4. **Three panels**: uploads to the PCE (last success, queued, failing, last error), unmanaged workloads (created
   today, waiting, dry run), ingestion (flows/s, dropped share).
5. The UDP ports with their host ports, for configuring exporters.

Style: plugger conventions (Catppuccin Mocha, Tailwind and Chart.js from CDN, opt-in `/brand/style.css`), PCE HREFs
as console links where shown.

## Alerts (plugger notifications, `POST /api/reports/publish`)

| Alert | Fires when | Clears when |
|---|---|---|
| Exporter silent | An exporter that sent flows has sent none for the silent-exporter time (default 15 min) | It sends again |
| No flows | No flows on any collector for the silent-exporter time, while at least one collector is on | Flows arrive |
| Uploads failing | FlowPilot's status is `upload_failing` | An upload succeeds |

Each problem alerts once when it starts and once when it clears ("back to normal"); no repeats while it lasts.
Alerts and the status line use the same evaluation. Alert state lives in the volume so a restart doesn't re-send
open alerts.

## Delivery

- Directory `flowpilot/` in this repo with `plugin.yaml`, `.plugger/metadata.yaml`, `Dockerfile`, `main.py`,
  `README.md`, `requirements.txt`, following `CLAUDE.md` (registry entry, portal card, README table, changelog,
  versions in sync, both validate scripts). Maturity: preview.
- Built by the existing plugins CI to `ghcr.io/<owner>/plugger-flowpilot:<version>`.

## Left to the builder

Python structure, polling interval (a few seconds), chart history resolution and retention (24 h at minimum),
restart backoff, exact wording of status lines and alerts, how settings map to variable names (one-to-one with
FlowPilot's `docs/configuration.md`), the README.

## Decided by me (not the user), easy to change

- Chart history and alert state stored in the volume.
- NetFlow on by default, other collectors off.
- Maturity "preview".
- Silent-exporter alert only for exporters that have sent at least once (an exporter never seen can't be named).
