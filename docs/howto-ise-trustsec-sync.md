# How to: Bridge Cisco ISE TrustSec (SGTs) into Illumio

If you run Cisco ISE with TrustSec, ISE owns the Security Group Tags (SGTs) and the identity context. Illumio owns workload segmentation with labels. Without a bridge, the two models speak different languages and nobody can say "the thing TrustSec calls `Contractors` is the same thing Illumio policy should treat as `Contractors`".

The `ise-sync` plugin mirrors ISE's TrustSec context into the PCE so both sides share one taxonomy, and surfaces host IP-SGT mappings as workloads.

This guide covers:

1. the **ise-sync** plugin (reads ISE via ERS, writes labels and workloads to the PCE),
2. reviewing the **dry-run** before anything is written,
3. optional reporting through the **notification bus**.

## What gets synced

| ISE (ERS API) | Illumio |
|---------------|---------|
| SGT definitions (`/ers/config/sgt`) | One label per SGT in a dedicated **`sgt` label dimension**, created automatically if it does not exist |
| Static IP-SGT mappings (`/ers/config/sgmapping`), single host (/32) | One unmanaged workload per host: interface plus its `sgt` label |
| Static IP-SGT mappings for subnets | Skipped (they are not single hosts) |

Everything is idempotent via `external_data_set=ise-sync` plus `external_data_reference`: missing items are created, changed ones updated, and workloads that do not carry the `ise-sync` data set are never touched. ISE is accessed **read-only**, and the plugin is **dry-run by default** on the PCE side.

## Prerequisites

- **ERS enabled** on ISE (the External RESTful Services API, default port 9060).
- An ISE account in the **ERS-Admin** or **ERS-Operator** group.
- Network reachability from the plugger host to ISE on the ERS port.

## Enable it

```bash
plugger install ise-sync
plugger run    # ise-sync is a daemon
```

Set the connection details as environment variables:

| Env var | Notes |
|---------|-------|
| `ISE_HOST` | Required. ISE host or IP |
| `ISE_ERS_USER` | Required. ERS account |
| `ISE_ERS_PASSWORD` | Required, secret. Masked in the dashboard and never logged |
| `ISE_PORT` | Default `9060` |

PCE credentials are injected by plugger. The plugin is a daemon with a dashboard and a **Sync now** button, and re-syncs every `POLL_INTERVAL` seconds (6 hours by default).

## Review the dry-run

`DRY_RUN=true` is the default. In dry-run nothing is written to the PCE: no labels, no label dimension, no workloads.

1. Open the plugin's dashboard from the plugger shell (it is proxied).
2. Check the **SGT chips**: every SGT that would become a label in the `sgt` dimension.
3. Check the **host IP-SGT workloads**: the /32 mappings that would become unmanaged workloads.
4. Use **Sync now** after changing settings to refresh the plan.

When it looks right, set `DRY_RUN=false` and let the next cycle (or **Sync now**) apply it.

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

## Use the data in Illumio

- **Shared vocabulary**: SGT names now exist as labels in the `sgt` dimension, so the same names mean the same thing in TrustSec and in Illumio. This also gives you a common taxonomy with Meraki Adaptive Policy, which uses SGTs too (see the [Meraki visibility guide](howto-meraki-visibility.md)).
- **Scope policy by SGT**: use the `sgt` label dimension in rulesets and rule scopes, alongside your existing app, env, role, and loc labels.
- **See SGT-tagged hosts**: host IP-SGT workloads appear in the map with their interface and `sgt` label, even without a VEN.
- **Provenance**: filter on the `ise-sync` data set to list everything this integration owns.

## Get a summary in Slack or Splunk

Each cycle publishes a summary to the notification bus. Route it centrally in `~/.plugger/config.yaml`, as in the [PCE expiry how-to](howto-pce-expiry-monitoring.md):

```yaml
plugger:
  outputs:
    - type: slack
      name: ise-slack
      webhook: https://hooks.slack.com/services/T.../B.../xxx
      filter:
        plugins: [ise-sync]
```

Verify with `plugger output test ise-slack`. A `splunk` output works the same way.

## Troubleshooting

- **Connection refused or HTTP 401/403**: ERS is not enabled on ISE, the port is wrong, or the account is not in the ERS-Admin / ERS-Operator group. Enable ERS in ISE settings and fix the group membership.
- **TLS errors**: `ISE_TLS_SKIP_VERIFY` defaults to `true`, so self-signed ISE certificates work out of the box. If you set it to `false`, ISE's certificate must chain to a CA the plugin trusts.
- **SGTs show but no workloads**: most IP-SGT mappings are subnets, and only single-host (/32) static mappings become workloads. Subnet mappings are skipped by design.
- **The `sgt` dimension is not there after a dry-run**: expected. Dry-run never creates the label dimension; it appears on the first real sync.
- **Nothing written**: `DRY_RUN` is still `true`.

## Roadmap and scope

This is **Phase 1 (visibility via ERS)**. Dynamic IP-to-SGT bindings, live session data and endpoint profiling need **pxGrid** (certificate onboarding) and are planned for later. Illumio-driven quarantine through ISE ANC is a separate enforcement-focused plugin (`ise-anc-responder`). ISE remains the source of truth for SGTs; this bridge is read-only on ISE by design.
