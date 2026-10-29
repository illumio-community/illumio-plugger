# meraki-sync

Imports **Cisco Meraki clients into Illumio as labeled unmanaged workloads** — the
IoT, BYOD, and branch devices that Meraki already sees but you can't put a VEN on.
They show up in the Illumio map and can be scoped by policy later.

This is **Phase 1 (visibility)** of the Meraki integration: a **daemon** that polls
Meraki on an interval, is **read-only on Meraki**, and is **dry-run-by-default on
the PCE**. It serves a small dashboard showing the discovered devices and the sync
plan, plus a "Sync now" button. Policy push to the Meraki edge is a separate,
later phase.

## What it does

1. Reads your Meraki org → networks → **clients** (seen within `CLIENT_TIMESPAN`).
2. Maps each client to an Illumio unmanaged workload:
   - `loc` label = Meraki network name
   - `role` label = Meraki's device-type prediction (falls back to manufacturer/OS)
   - optional fixed `app` label via `APP_LABEL`
   - interface from the client's IP
3. Writes them idempotently: every workload is stamped with
   `external_data_set=meraki-sync` and `external_data_reference=<meraki client id>`,
   so re-runs **update in place** (create missing, update changed) instead of
   duplicating.
4. Publishes a summary report (discovered / new / updated / skipped) to the bus.

## Safety

`DRY_RUN=true` (the default) logs and reports exactly what *would* be synced
**without writing anything to the PCE**. Review the dry-run report, then set
`DRY_RUN=false` to apply. The write path only ever touches workloads carrying the
`meraki-sync` data set — it never modifies VEN-managed or hand-created workloads.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `MERAKI_API_KEY` | _(required, secret)_ | Meraki Dashboard API key (org-scoped) |
| `MERAKI_ORG_ID` | _(auto)_ | Org ID; auto-detected if the key sees exactly one org |
| `MERAKI_NETWORK_IDS` | _(all)_ | Comma-separated network IDs to scan |
| `POLL_INTERVAL` | `21600` | Seconds between sync cycles (default 6h) |
| `CLIENT_TIMESPAN` | `86400` | Import clients seen within the last N seconds |
| `MAX_CLIENTS_PER_NETWORK` | `5000` | Per-network safety cap |
| `EXTERNAL_DATA_SET` | `meraki-sync` | Illumio provenance tag for idempotency |
| `APP_LABEL` | _(none)_ | Optional fixed `app` label on every device |
| `DRY_RUN` | `true` | Log/report without writing (safe default) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PCE API calls |

PCE credentials (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`,
`PCE_API_SECRET`) are injected automatically by plugger.

## Dashboard & polling

Runs as a daemon, re-syncing every `POLL_INTERVAL` seconds (6h by default — Meraki
inventory is slow-moving, and change detection keeps steady-state PCE writes
minimal). The dashboard (proxied through the plugger shell) lists the discovered
devices and the sync plan, and a **Sync now** button triggers an immediate cycle.
A `/healthz` endpoint backs plugger's health checks.

## Notes & roadmap

- **Labeling is intentionally simple in Phase 1** (`loc` + `role`). Refine it to
  your scheme once the device inventory looks right.
- The official `meraki` SDK handles Dashboard API pagination and rate limiting.
- **Later phases** (not in this plugin): push Illumio label intent to Meraki MX
  L3 firewall rules, and bridge Illumio labels ↔ Meraki Adaptive Policy (SGT).
