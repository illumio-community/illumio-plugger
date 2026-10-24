# FlowPilot

Collect NetFlow, IPFIX, sFlow and syslog-style text flows from routers and firewalls and send them to the Illumio PCE, without installing FlowLink. The plugin runs the FlowPilot flow collector, shows an ingestion-health dashboard, and raises plugger notifications when something stops.

**Maturity: preview.** The core promise: **you'll know when an exporter goes silent.**

## How it works

- The image contains the FlowPilot collector binary (`/usr/local/bin/flowlink`, unchanged).
- `main.py` (on the vendored `plugger_sdk.py`) maps the plugger settings to `FLOWPILOT_*` environment variables and runs the binary as a child process. It restarts it with a backoff (1s up to 30s) if it exits, and stops it cleanly (SIGTERM, then kill after 10s) on shutdown.
- FlowPilot's log, including its `FLOWPILOT_STATS` lines, goes to the plugin's stdout, so `plugger logs flowpilot` shows it.
- FlowPilot's stats endpoint listens on `127.0.0.1:9180` inside the container only. The plugin polls `/stats` every 5 seconds to drive the dashboard and the alerts.
- PCE address, org and API credentials come from plugger (`PCE_*`); FlowPilot picks them up itself. There is nothing to enter for them.

## Binary

The image needs a linux `flowlink` binary (a static build of **FlowPilot**, [github.com/alexgoller/flowpilot](https://github.com/alexgoller/flowpilot), Apache-2.0) in the `flowpilot/` directory **before `docker build`**; the Dockerfile copies it to `/usr/local/bin/flowlink`. Without it, the image build fails.

Until FlowPilot cuts its first tagged release, build the binary locally from that repo and copy it in. Once a release exists, the image switches to downloading the pinned release asset (`flowpilot-<ver>-x86_64-linux`) and verifying `SHA256SUMS`. (`flowpilot -version` prints the running version, e.g. `FlowPilot version: 0.9.0`.)

## Install

```bash
cp /path/to/flowlink flowpilot/flowlink
docker build -t plugger-flowpilot:latest flowpilot/
plugger install flowpilot
```

Then open the settings form, enable the collectors you need and point your exporters at the plugin's UDP port.

## Settings

| Group | Settings |
|---|---|
| Collectors | `NETFLOW_*`, `IPFIX_*`, `SFLOW_*`, `TEXT_*`: `_ENABLED` and `_PORT` (defaults 2055, 4739, 6343, 514; only NetFlow is on by default) plus `_REMOTE_ADDRS`, an optional allow-list of exporter addresses |
| Text parser | `TEXT_SRC_IP`, `TEXT_DST_IP`, `TEXT_DST_PORT`, `TEXT_PROTOCOL` (required when text is on); `TEXT_OCTETS`, `TEXT_ICMP_TYPE`, `TEXT_ICMP_CODE`, `TEXT_TIMESTAMP`, `TEXT_TIMESTAMP_FORMAT`, `TEXT_ONLY_RECS`, `TEXT_FIELD_SEPARATOR`, `TEXT_ATTRIBUTE_SEPARATOR` |
| Basics | `AGGREGATION_MINUTES` (10), `VERIFY_PCE_CERT` (true) |
| Unmanaged workloads | `UNMANAGED_ENABLED`, `UNMANAGED_DRY_RUN`, `UNMANAGED_NETWORKS`, `UNMANAGED_MIN_FLOWS`, `UNMANAGED_MAX_CREATES_PER_WINDOW`, `UNMANAGED_MAX_CREATES_PER_DAY`, `UNMANAGED_LABEL_RULES` (compact `cidr=key:value,...;...` or JSON) |
| Alerts | `SILENT_EXPORTER_MINUTES` (15) |

Each setting maps to `FLOWPILOT_<NAME>` (collector ports to `FLOWPILOT_<C>_PORTS`). FlowPilot validates the configuration at start; if it rejects a setting, its error (which names the variable) is shown as a red banner on the dashboard and the plugin reports unhealthy.

## Dashboard

Served through plugger at `/plugins/flowpilot/ui/`:

1. Status line: flows arriving, exporter silent, no flows, or uploads failing. Same evaluation as the alerts.
2. Flows per second chart (total plus one line per exporter), ranges 15m / 1h / 24h.
3. Exporter table: status dot, address, protocol, last flow, flows/s with trend, templates, decode errors; datagrams rejected by an allow-list appear as their own row.
4. Panels: uploads to the PCE, unmanaged workloads, ingestion.
5. UDP container ports. Until plugger issue #43 (fixed host ports), check `plugger status flowpilot` for the mapped host port to point exporters at.

## Alerts

Sent through plugger's report framework (`POST /api/reports/publish`), once when a problem starts and once when it clears.

| Alert | Severity | Fires when | Clears when |
|---|---|---|---|
| `exporter_silent` | warning | An exporter that sent flows has sent no new flows for `SILENT_EXPORTER_MINUTES` | It sends again |
| `no_flows` | warning | A collector is on and no flow arrived for `SILENT_EXPORTER_MINUTES` | Flows arrive |
| `uploads_failing` | critical | FlowPilot status is `upload_failing` | An upload succeeds |

Only exporters seen at least once can be reported silent. Silence is measured by the plugin while it is running, so a plugin restart does not cause an immediate false alert. A silent exporter or failing upload never makes the plugin unhealthy (restarting would not help).

## Volume

`/data` holds FlowPilot's data directory (`/data/flowpilot`: queued uploads, unmanaged workload state) and the plugin's chart history, alert state and exporter last-seen (`/data/plugin`). Alert state is persisted so a restart does not re-send open alerts.
