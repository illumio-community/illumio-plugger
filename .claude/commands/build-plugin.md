Build an Illumio Plugger plugin from a user description.

Ask the user what the plugin should do if not already clear from context. Then:

1. Ask whether they want a Go or shell plugin (recommend Go for anything with a UI or complex logic, shell for simple periodic scripts).

2. Run `plugger create <name> -t <go|shell>` to scaffold the project.

3. Edit the generated files based on what the plugin needs to do:
   - **main.go or entrypoint.sh**: Implement the actual plugin logic — PCE API calls, data processing, etc.
   - **plugin.yaml**: Set the correct schedule mode (daemon/cron/event), env vars, resource limits.
   - **.plugger/metadata.yaml**: Declare any ports, config requirements, volumes, and plugin info.
   - **Dockerfile**: Add any extra dependencies the plugin needs.

4. For PCE API calls, use these patterns:
   - Go: `net/http` with basic auth (`PCE_API_KEY:PCE_API_SECRET`), base URL `https://{PCE_HOST}:{PCE_PORT}/api/v2/orgs/{PCE_ORG_ID}`
   - Shell: the `pce_api` helper in the template already handles auth

5. Key PCE API endpoints to know:
   - `GET /workloads` — list workloads
   - `GET /labels` — list labels  
   - `GET /label_groups` — list label groups
   - `GET /sec_policy/draft/rule_sets` — list rulesets
   - `GET /events` — get audit events
   - `GET /traffic_flows/traffic_analysis_queries` — traffic flow queries

6. Build the Docker image: `docker build -t <name>:latest .`

7. Test it: `plugger install plugin.yaml && plugger start <name> && plugger logs <name> -f`

8. Show the user the final `plugger status <name>` output.

Always write clean, production-quality code. Include error handling, structured logging, and graceful shutdown for Go plugins.

## Integrating an external system (third-party API ↔ PCE)

Many plugins bridge a vendor's API and the Illumio PCE — pull an inventory in, or push PCE
data out. The repo's integration plugins (`meraki-sync`, `nozomi-sync`, `fortigate-sync`,
`infoblox-ipam-sync`) are all **daemon + Python**, built on the `plugger_sdk`. Follow these
patterns; name the exemplar you're copying.

### 1. Mode choice

- **Default to `daemon` + `plugger_sdk`** for any ongoing integration or sync. You get a
  dashboard, a built-in `/healthz`, and an on-demand trigger for free. Exemplars:
  `meraki-sync`, `nozomi-sync`.
- Use **`cron`** only for a periodic one-shot report that does its work and exits — e.g.
  `pce-expiry-watch` (checks expiries, publishes a report, exits).

### 2. Daemon skeleton with plugger_sdk

Vendor the SDK as `plugger_sdk.py` next to `main.py` (single-file copy, not a PyPI package).

```python
from plugger_sdk import Plugin

app = Plugin("acme-sync")

@app.poll(interval_env="POLL_INTERVAL", default=21600)   # the sync loop; initial run + every N seconds
def sync(pce):                                            # pce is a ready illumio PolicyComputeEngine
    ...
    app.update_state({"last_sync": ..., "created": ...})  # feed the dashboard

@app.api("POST", "/api/sync")                             # on-demand run from the dashboard button
def trigger_sync(request):
    app.trigger_poll()
    return {"status": "triggered"}

@app.dashboard                                            # return an HTML string (theme auto-injected)
def dashboard():
    s = app.state
    return f"<!doctype html>...{s.get('created', 0)}..."

if __name__ == "__main__":
    app.run()
```

What the SDK gives you: `app.pce` (connected `PolicyComputeEngine`), `app.ensure_label(key, value)`
(find-or-create, returns href), `app.report(...)`, `app.log`, `app.pce_link(href)` (API HREF →
console URL), `app.state` / `app.update_state(...)`, `app.trigger_poll()`, and a built-in
`/healthz`. The `@app.poll` loop runs once at startup and then on the interval (or when triggered).

### 3. External API client hygiene

- **Credentials are `secret: true` env vars** in `plugin.yaml` and `type: secret` in
  `metadata.yaml`. Reference the *names* (`MERAKI_API_KEY`, `NOZOMI_KEY_TOKEN`), never values.
- **Prefer the vendor's official SDK** — it handles pagination and 429/rate-limit backoff for you.
  `meraki-sync` uses the `meraki` SDK with `total_pages="all"` and lets it retry.
- **Otherwise handle it yourself**: paginate, honor `429`/`Retry-After`, set request timeouts, and
  re-auth on `401` once (see `nozomi-sync`'s page loop and JWT refresh).
- **Tolerate one bad sub-resource** — catch per-item/per-network errors, log a warning, and keep
  going instead of aborting the whole sync (`meraki-sync` skips a network whose clients fail to
  fetch).

### 4. Idempotent sync INTO the PCE

`meraki-sync` is the worked example. Represent external assets as **unmanaged workloads** and make
re-runs upsert instead of duplicate:

- Stamp every workload you own with `external_data_set="<plugin-name>"` and
  `external_data_reference="<stable external id>"` (Meraki client id, Nozomi asset id, …).
- Find existing ones by querying `GET /workloads?external_data_set=<plugin-name>` and keying on
  `external_data_reference`.
- Find-or-create labels with `app.ensure_label(key, value)`.
- Write with `pce.put("/workloads/bulk_create")` / `pce.put("/workloads/bulk_update")` in batches
  of **≤ 1000** (use ~500).
- **Compute a change signature** (sorted label hrefs + interfaces) and only `bulk_update` what
  actually changed — skip unchanged workloads.
- **NEVER touch workloads outside your own `external_data_set`.** Don't modify VEN-managed or
  hand-created workloads. Scope every read and write by your set.

### 5. Safety — default to dry run when you WRITE

Any plugin that writes to the PCE must default `DRY_RUN=true`. In dry-run, compute and surface the
plan (would-create / would-update counts, sample rows) in the logs, dashboard, and report, but
write nothing. Operators set `DRY_RUN=false` to apply. Both `meraki-sync` and `nozomi-sync` do this;
show the mode as a badge on the dashboard.

### 6. Label mapping — keep it simple

Mapping external attributes to Illumio labels is heuristic. Map a small, obvious set (e.g. network →
`loc`, device type → `role`) and make it configurable; don't over-map in v1. `nozomi-sync` shows a
configurable `LABEL_MAP` with candidate-key fallbacks — reach for that only when field names vary by
product/version.

### 7. Reporting

Publish results with `app.report(title, body, severity, tags, data)` — `severity` is
`info`/`warning`/`critical`, `body` is markdown. Plugger routes it to Slack/email/webhook centrally;
the plugin doesn't know or care where it lands. Report the sync outcome every cycle (and warn on
errors), as `meraki-sync` does.
