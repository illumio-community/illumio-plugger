# How to: Monitor PCE Expiry (Service Accounts, Pairing Keys, License, TLS Cert)

An expired service-account API key silently breaks every integration that uses it. An exhausted pairing key stops onboarding new workloads. An expired PCE TLS certificate breaks every VEN and browser at once. The `pce-expiry-watch` plugin makes sure you hear about each of these weeks in advance, in the channels you already watch.

This guide wires three pieces together:

1. the **pce-expiry-watch** plugin (finds what is about to expire),
2. the **notification bus** (routes alerts to Slack, Teams, email),
3. the native **Splunk output** (ships structured events to your SIEM).

## What gets checked

| Check | Source | Notes |
|-------|--------|-------|
| **Service accounts** | PCE API `service_accounts` | API-key expiry |
| **Pairing keys** | PCE API `pairing_profiles` | Active key lifespan **and** uses remaining |
| **PCE license** | `GET /license` (configurable) | Best-effort. The endpoint varies by PCE version; if it is unavailable the check is quietly skipped and the run continues |
| **PCE TLS certificate** | TLS handshake to `PCE_HOST:PCE_PORT` | `notAfter` is read directly off the certificate |

Severity model:

- **critical**: expires within `CRITICAL_DAYS` (default 7) or is already expired
- **warning**: expires within `WARN_DAYS` (default 30)
- Anything further out is logged but not reported

## Enable it

```bash
plugger install pce-expiry-watch
plugger run    # the scheduler picks the cron plugin up
```

It is a cron plugin and runs daily at 08:00 (`0 8 * * *` in `plugin.yaml`). Expiry changes slowly, so daily is plenty.

PCE credentials are injected by plugger. Everything else is optional tuning via environment variables:

| Env var | Default | Description |
|---------|---------|-------------|
| `WARN_DAYS` | `30` | Warn when an object expires within this many days |
| `CRITICAL_DAYS` | `7` | Escalate to critical within this many days |
| `PAIRING_USES_WARN` | `5` | Warn when a pairing key has this many uses left or fewer |
| `CHECK_SERVICE_ACCOUNTS` | `true` | Toggle the service-account check |
| `CHECK_PAIRING_KEYS` | `true` | Toggle the pairing-key check |
| `CHECK_LICENSE` | `true` | Toggle the license check |
| `CHECK_TLS_CERT` | `true` | Toggle the TLS-certificate check |
| `LICENSE_API_PATH` | `/license` | Org-scoped API path for the license object |
| `REPORT_ALL_CLEAR` | `false` | Also send an info report when nothing is expiring |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PCE API calls |

Tip: set `REPORT_ALL_CLEAR=true` for the first week so you can confirm the pipeline works end to end even when nothing is expiring.

## Route the alerts

The plugin only publishes reports; where they go is configured centrally in `~/.plugger/config.yaml` (see the *Reporting Framework* chapter in the portal handbook). Send expiry warnings to Slack and a daily digest to email:

```yaml
plugger:
  outputs:
    - type: slack
      name: expiry-slack
      webhook: https://hooks.slack.com/services/T.../B.../xxx
      filter:
        plugins: [pce-expiry-watch]
        severity: [warning, critical]

    - type: email
      name: expiry-email
      smtpHost: smtp.example.com
      smtpPort: 587
      from: plugger@example.com
      to: [platform-team@example.com]
      filter:
        plugins: [pce-expiry-watch]
```

Microsoft Teams works the same way with `type: teams` and a `webhook`. Verify delivery without waiting for something to expire:

```bash
plugger output test expiry-slack
# or hit the dashboard API directly (the output name is the last path segment, no body):
curl -X POST http://localhost:8800/api/reports/test/expiry-slack
```

## Ship to Splunk

The native `splunk` output delivers each report to the Splunk HTTP Event Collector (HEC) at `/services/collector/event` as a **structured event**. Report fields (`plugin`, `severity`, `title`, `tags`, `data`) are indexed directly, so no `props.conf` field extraction is needed.

> **Why HEC?** HEC is Splunk's standard method for *push* ingestion — applications and services sending events over HTTP(S). Splunk recommends it over forwarders for this kind of source (its own syslog solution, SC4S, also ships events via HEC). Forwarders are the standard method for the other pattern — tailing files or pulling on a schedule — which isn't what plugger does. Since plugger pushes structured JSON reports, HEC is the idiomatic fit. On the Splunk side HEC can live on the indexers or on a dedicated heavy-forwarder HEC tier (for independent scaling); that's transparent to plugger — just point `hecUrl` at whatever endpoint or load balancer you're given.

Add an output:

```yaml
plugger:
  outputs:
    - type: splunk
      name: siem-expiry
      hecUrl: https://splunk.example.com:8088
      hecTokenEnv: SPLUNK_HEC_TOKEN
      index: illumio
      sourcetype: plugger:report
      tlsSkipVerify: false
      filter:
        plugins: [pce-expiry-watch]
        severity: [warning, critical]
```

Or add it from the CLI instead of editing the file:

```bash
plugger output add siem-expiry --type splunk \
  --hec-url https://splunk.example.com:8088 \
  --hec-token-env SPLUNK_HEC_TOKEN \
  --index illumio \
  --plugins pce-expiry-watch --severity warning,critical
```

| Field | Description |
|-------|-------------|
| `hecUrl` | HEC base URL, or a full `/services/collector` endpoint. Plugger appends `/services/collector/event` when you give the base |
| `hecTokenEnv` | Name of the env var holding the HEC token (preferred, keeps the secret out of the file) |
| `hecToken` | Alternative: the token value or a `${ENV}` expansion |
| `index` | Optional target index |
| `sourcetype` | Default `plugger:report` |
| `source` | Default `plugger` |
| `tlsSkipVerify` | Default `false`. Set `true` for a self-signed lab HEC |

Provide the token in plugger's environment, then restart plugger so it reloads the config:

```bash
export SPLUNK_HEC_TOKEN='xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
# restart plugger from the same shell/environment so it inherits the variable
```

Confirm an event arrives:

```bash
plugger output test siem-expiry
# or: curl -X POST http://localhost:8800/api/reports/test/siem-expiry
```

> **No Splunk handy?** Use [`tools/mock-hec`](../tools/mock-hec/) — a tiny stdlib
> HTTP Event Collector stand-in that validates the HEC token and pretty-prints
> every event plugger sends. Run `python3 tools/mock-hec/mock_hec.py`, point
> `hecUrl` at `http://localhost:8088`, and `plugger output test` to see the exact
> payload.

In digest mode (`aggregate: true` with a `schedule`), plugger sends the buffered reports as newline-delimited JSON in a single HEC call.

### Alerts and dashboards in Splunk

Because the events are structured, you can search them directly. Adjust field names to match what you see in your first events (the `data.items{}` array carries the per-object details, including days to expiry):

```
index=illumio sourcetype="plugger:report" plugin="pce-expiry-watch" severity=critical
```

Ideas:

- A Splunk alert on `severity=critical` for `plugin="pce-expiry-watch"`, triggered per result, for paging.
- A dashboard table expanding `data.items{}` to list every object with its days to expiry, sorted ascending.
- A single-value panel counting open `warning` and `critical` reports over the last 24 hours.

## Troubleshooting

- **No license findings**: expected on PCE versions without a license endpoint at `/license`. Set `LICENSE_API_PATH`, or `CHECK_LICENSE=false` to silence it.
- **Nothing arrives in Splunk**: check that `SPLUNK_HEC_TOKEN` is set in the environment plugger runs in, that the HEC token is enabled and allowed to write to `index`, and use `tlsSkipVerify: true` temporarily if the HEC certificate is self-signed.
- **Too noisy**: lower `WARN_DAYS`, or filter the Slack output to `severity: [critical]` and keep warnings in email or Splunk.
