# Dashboard: access badges, metrics actions, collapsible config

Findings
- The access badge (d235bdb) was only ever added to the PORTAL; the plugger dashboard
  templates never rendered it. Also plugins.json manifests carry no `access` at all —
  `bin/plugger` (and the running daemon) date from Nov 4, before the field existed, so
  installs never persisted it. Fix needs: dashboard rendering + a registry fallback for
  installs that predate the field (and a fresh daemon binary).
- Metrics page rebuilds every card each 5s (charts flicker, clicks can be swallowed) and
  gives stopped plugins the same sparkline card as running ones.

## Access badge
- [x] registry.Plugin: add `Access` (json access) so the cached registry can answer it
- [x] registry.Manager.LoadCached(): cached registries only, no network
- [x] dashboard: resolveAccess(plugins) -> map name->readonly|readwrite
      (manifest value > cached registry > readonly default)
- [x] badge on plugin cards (index), detail header, config section summaries
- [x] test: manifest wins, registry fallback, default

## Metrics page
- [x] running plugins first with sparklines; "Not running" group below, compact, no charts
- [x] Start / Stop / Restart buttons per card (POST existing endpoints), refresh on completion
- [x] update in place when the plugin set/states are unchanged (no chart destroy/rebuild),
      hold refresh while an action is in flight
- [x] metrics API: expose `enabled`/`mode` if needed for cron (cron plugins "stopped" = idle)

## Config page
- [x] each plugin section becomes <details>, collapsed by default; summary shows name,
      state, access, field count + modified count
- [x] Expand all / Collapse all; remember open sections in localStorage
- [x] inputs inside closed <details> still submit (verify)

## Verify
- [x] go test ./internal/... ; go vet
- [x] make build, restart daemon on the new binary, curl pages: badge present, config
      details markup, metrics JSON, action POST from metrics
- [x] portal changelog (Unreleased/next), commit, push

## Review (done 2026-11-13)
- Verified live on :8800 after rebuild+restart: 6 read-only / 2 read-write badges on /,
  /config and detail pages (flowpilot + ven-fleet-manager resolved via registry fallback
  because their stored manifests predate the field); 8 <details> config sections;
  /api/metrics carries mode; metrics page JS + config JS pass node --check.
- Contrast: every light-mode badge pair >= 4.5:1; dark grey badges 2.6 -> 8.5 and
  5.2 -> 10.0.
- Pushed as one commit on main; changelog card v0.15.9 added — tag not cut (user's call).

## Follow-up (2026-11-13, after v0.15.9)
- [x] v0.15.9 tagged; release run 43402335209 green (12 assets + cask); plugin images green
- [x] brew upgrade -> plugger 0.15.9; local daemon relaunched from /opt/homebrew/bin/plugger
- [x] /registry: combinable filters (mode/UI/status/access) + access & maturity badges
- [x] portal: light-mode badge palette fixed (already had access badge + filter since d235bdb)
- [x] v0.15.10 tagged: release green (12 assets + cask), brew 0.15.10, daemon relaunched on it
- [x] LICENSE added (Apache-2.0, Copyright 2026 Illumio, Inc.), packaged in deb/rpm (420adc4)
- [x] v0.15.11 tagged (1a5ac47): release green (12 assets + cask), brew 0.15.11, daemon relaunched on it (pid 58922)
