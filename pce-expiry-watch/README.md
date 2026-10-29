# pce-expiry-watch

Warns you **before** PCE objects expire. A scheduled (cron) plugin that checks
the expiry of selected PCE objects on each run and publishes a report through
the plugger reporting bus (Slack / email / webhook) for anything inside the
warning window.

Every check is independently toggleable, and all thresholds are configurable.

## What it checks

| Check | Source | Notes |
|-------|--------|-------|
| **Service accounts** | `GET /service_accounts` | API-key expiry on service accounts |
| **Pairing keys** | `GET /pairing_profiles` | Active key lifespan **and** uses remaining |
| **PCE license** | `GET /license` (configurable) | Best-effort — endpoint varies by PCE version |
| **PCE TLS certificate** | TLS handshake to `PCE_HOST:PCE_PORT` | `notAfter` read directly, no API call |

## Severity

- **critical** — expires within `CRITICAL_DAYS` (default 7), or already expired
- **warning** — expires within `WARN_DAYS` (default 30)
- Anything further out is logged but not reported.

Routing (which channel each severity goes to) is configured centrally in
`~/.plugger/config.yaml` — the plugin just publishes.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `WARN_DAYS` | `30` | Warn when an object expires within this many days |
| `CRITICAL_DAYS` | `7` | Escalate to critical within this many days |
| `PAIRING_USES_WARN` | `5` | Warn when a pairing key has ≤ this many uses left |
| `CHECK_SERVICE_ACCOUNTS` | `true` | Toggle the service-account check |
| `CHECK_PAIRING_KEYS` | `true` | Toggle the pairing-key check |
| `CHECK_LICENSE` | `true` | Toggle the license check |
| `CHECK_TLS_CERT` | `true` | Toggle the TLS-certificate check |
| `LICENSE_API_PATH` | `/license` | Org-scoped API path for the license object |
| `REPORT_ALL_CLEAR` | `false` | Also send an info report when nothing is expiring |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for PCE API calls |

PCE credentials (`PCE_HOST`, `PCE_PORT`, `PCE_ORG_ID`, `PCE_API_KEY`,
`PCE_API_SECRET`) are injected automatically by plugger.

## Schedule

Daily at 08:00 by default (`0 8 * * *` in `plugin.yaml`). Expiry is slow-moving,
so a daily check is plenty; adjust the cron expression if you want it more often.

## Caveats

- **License** — the PCE license object is not exposed by a stable public API on
  all PCE versions. The check degrades gracefully (logs and skips on a non-200)
  and the endpoint is overridable via `LICENSE_API_PATH`. If your PCE exposes it
  elsewhere, point this at the right org-scoped path.
- **Pairing-key uses** — `total_use_count` on a pairing profile is an aggregate
  counter; `uses remaining` is a best-effort signal meant to flag a profile worth
  a human look, not an exact per-key count. Key-lifespan expiry is exact.

## Local testing

`publish_report()` is a no-op when `PLUGGER_URL` is unset, so you can dry-run the
checks against a PCE without sending anything to your output channels:

```bash
PCE_HOST=... PCE_PORT=8443 PCE_ORG_ID=1 \
PCE_API_KEY=... PCE_API_SECRET=... \
python3 main.py
```

It logs every finding to stdout regardless of whether a report is published.
