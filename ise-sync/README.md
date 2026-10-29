# ise-sync

Bridges **Cisco ISE TrustSec context into Illumio**. ISE is the authoritative
source for Security Group Tags (SGTs) and identity; this plugin mirrors that
context into the PCE so your Illumio policy model and TrustSec share a taxonomy.

This is **Phase 1 (visibility, ERS)**: a **daemon** that polls ISE's ERS API,
**read-only on ISE**, **dry-run-by-default on the PCE**, with a dashboard.

## What it does

1. **SGT definitions → Illumio labels.** Reads `/ers/config/sgt` and ensures a
   label per SGT in a dedicated `sgt` dimension (created automatically if it
   doesn't exist). This gives Illumio and TrustSec a shared segmentation
   vocabulary.
2. **Host IP-SGT mappings → unmanaged workloads.** Reads `/ers/config/sgmapping`
   and, for each **single-host (/32)** static mapping, creates an Illumio
   unmanaged workload (interface + `sgt` label). Subnet mappings are skipped
   (they aren't single hosts).

Idempotent via `external_data_set=ise-sync` + `external_data_reference`
(create missing, update changed; never touches non-ise-sync workloads).
Publishes a summary to the reporting bus.

## Safety

`DRY_RUN=true` (default) logs/reports/shows what *would* sync without writing to
the PCE (no labels, no label dimension, no workloads). Review, then set
`DRY_RUN=false` to apply.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `ISE_HOST` | _(required)_ | Cisco ISE host/IP |
| `ISE_PORT` | `9060` | ERS API port |
| `ISE_ERS_USER` | _(required)_ | ERS account (ERS-Admin or ERS-Operator) |
| `ISE_ERS_PASSWORD` | _(required, secret)_ | ERS account password |
| `ISE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for ISE |
| `SGT_LABEL_KEY` | `sgt` | Illumio label dimension for SGTs |
| `IMPORT_SGTS` | `true` | Mirror SGT definitions as labels |
| `IMPORT_IP_SGT` | `true` | Import host IP-SGT mappings as workloads |
| `MAX_SGTS` / `MAX_MAPPINGS` | `2000` / `10000` | Safety caps |
| `POLL_INTERVAL` | `21600` | Seconds between sync cycles (6h) |
| `DRY_RUN` | `true` | Log/show without writing (safe default) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PCE API calls |

PCE credentials are injected automatically by plugger. ERS must be enabled on
ISE and the account must be in the ERS-Admin/ERS-Operator group.

## Dashboard

Runs as a daemon (re-syncs every `POLL_INTERVAL`), serves a dashboard listing the
synced SGTs and the host IP-SGT workloads, with a **Sync now** button, and a
`/healthz` endpoint for plugger health checks.

## Roadmap (not in this phase)

- **pxGrid**: dynamic IP↔SGT bindings, live session directory, endpoint
  profiling — needs pxGrid (cert onboarding), out of scope for the ERS phase.
- **ise-anc-responder**: Illumio-driven ANC quarantine of non-agentable
  endpoints via ISE (a separate, enforcement-focused plugin).
- Note: ISE is the SGT source of truth — this bridge is read-only on ISE by design.
