# How to: See Meraki-Only Devices (IoT, BYOD, Branch) in the Illumio Map

Some of the most interesting devices on your network are the ones you cannot put a VEN on: cameras, printers, badge readers, phones, guest laptops, branch gear. Cisco Meraki already sees them, because they are clients on its switches and access points, but Illumio does not. Those are blind spots in the map and in any policy you write.

The `meraki-sync` plugin closes that gap. It reads Meraki clients and creates them in the PCE as **labeled unmanaged workloads**, so they appear in the Illumio map and can be scoped by policy later.

This guide covers:

1. the **meraki-sync** plugin (discovers devices and writes them to the PCE),
2. reviewing the **dry-run** before anything is written,
3. optional alerts through the **notification bus** (Slack, Splunk, email).

## What gets synced

| Meraki | Illumio |
|--------|---------|
| Org, networks, clients seen within `CLIENT_TIMESPAN` | One unmanaged workload per client |
| Network name | `loc` label |
| Device-type prediction (falls back to manufacturer / OS) | `role` label |
| (optional) `APP_LABEL` | Fixed `app` label on every device |
| Client IP | Workload interface |

Every workload is stamped with `external_data_set=meraki-sync` and `external_data_reference=<meraki client id>`. Re-runs therefore **update in place** (create missing, update changed) instead of duplicating, and the write path only ever touches workloads carrying that data set. VEN-managed and hand-created workloads are never modified.

Meraki is accessed **read-only**. The plugin is also **dry-run by default** on the PCE side.

## Enable it

```bash
plugger install meraki-sync
plugger run    # meraki-sync is a daemon
```

Set the Meraki Dashboard API key as a secret environment variable (it is marked `secret`, so it is masked in the dashboard and never logged):

| Env var | Notes |
|---------|-------|
| `MERAKI_API_KEY` | Required. Meraki Dashboard API key (org-scoped) |
| `MERAKI_ORG_ID` | Optional. Auto-detected if the key sees exactly one org |

PCE credentials are injected by plugger. The plugin runs as a daemon with a small dashboard and a **Sync now** button, and re-syncs every `POLL_INTERVAL` seconds (6 hours by default, because Meraki inventory moves slowly).

## Review the dry-run

`DRY_RUN=true` is the default, so the first cycle writes nothing to the PCE.

1. Open the plugin's dashboard from the plugger shell (it is proxied, no extra port to expose).
2. Check the **discovered devices** list: do the networks and device types look like what you expect?
3. Check the **sync plan**: how many workloads would be created, updated, or skipped.
4. Use **Sync now** after changing any setting to see a fresh plan immediately.

When the plan looks right, set `DRY_RUN=false` and let the next cycle (or **Sync now**) apply it. Labeling is intentionally simple in this phase (`loc` + `role`), so it is worth refining your scheme once the inventory looks right.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `MERAKI_API_KEY` | _(required, secret)_ | Meraki Dashboard API key (org-scoped) |
| `MERAKI_ORG_ID` | _(auto)_ | Org ID; auto-detected if the key sees exactly one org |
| `MERAKI_NETWORK_IDS` | _(all)_ | Comma-separated network IDs to scan |
| `POLL_INTERVAL` | `21600` | Seconds between sync cycles (6h) |
| `CLIENT_TIMESPAN` | `86400` | Import clients seen within the last N seconds |
| `MAX_CLIENTS_PER_NETWORK` | `5000` | Per-network safety cap |
| `EXTERNAL_DATA_SET` | `meraki-sync` | Illumio provenance tag for idempotency |
| `APP_LABEL` | _(none)_ | Optional fixed `app` label on every device |
| `DRY_RUN` | `true` | Log/report without writing (safe default) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PCE API calls |

## Use the data in Illumio

Once the workloads exist they behave like any other unmanaged workload:

- **Explore**: filter the Illumio map and workload list by `loc` (which site or network) and `role` (camera, printer, phone, and so on) to see what talks to what.
- **Scope policy**: write rules against `role` and `loc` labels instead of IP addresses, for example allowing only your NVR role to reach the camera role. Start in visibility and move to enforcement deliberately.
- **Find provenance**: filter on the `meraki-sync` data set to list everything this integration owns.

## Get a summary in Slack or Splunk

After each cycle the plugin publishes a report (discovered / new / updated / skipped) to the notification bus. Route it centrally in `~/.plugger/config.yaml`, exactly like in the [PCE expiry how-to](howto-pce-expiry-monitoring.md):

```yaml
plugger:
  outputs:
    - type: slack
      name: meraki-slack
      webhook: https://hooks.slack.com/services/T.../B.../xxx
      filter:
        plugins: [meraki-sync]
```

Verify delivery with `plugger output test meraki-slack`. A `splunk` output works the same way (see the Splunk section of that guide).

## Troubleshooting

- **No devices discovered**: widen `CLIENT_TIMESPAN` (clients only count if seen within it), confirm `MERAKI_ORG_ID` points at the right org, check that the API key has access to the org's networks, and check `MERAKI_NETWORK_IDS` is not filtering everything out.
- **Org not detected**: if the key sees more than one org, set `MERAKI_ORG_ID` explicitly.
- **Nothing written to the PCE**: `DRY_RUN` is still `true`. Set it to `false`.
- **Some networks truncated**: raise `MAX_CLIENTS_PER_NETWORK` if a network exceeds the safety cap.
- **Dashboard shows an error**: check the plugin logs with `plugger logs meraki-sync` for Meraki API or PCE auth errors.

## Roadmap

This plugin is **Phase 1: visibility**. Later phases are not part of it: pushing Illumio label intent to Meraki MX L3 firewall rules (Phase 2), and bridging Illumio labels with Meraki Adaptive Policy / SGTs (Phase 3). If you also run Cisco ISE, see the companion [ISE TrustSec sync guide](howto-ise-trustsec-sync.md).
