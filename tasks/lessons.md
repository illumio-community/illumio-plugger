# Lessons

## Restarting the local plugger daemon onto a fresh binary
- The daemon runs as `./bin/plugger run --addr 0.0.0.0:8800` with
  `DOCKER_HOST=unix:///Volumes/MacMini-4TB/alex-extern/.docker/run/docker.sock`
  and logs to `~/.plugger/daemon.log` (= /Volumes/MacMini-4TB/alex-extern/.plugger/daemon.log).
- SIGTERM shuts it down gracefully (stops each scheduler/container); allow ~10–30s.
  Port 8800 frees only on process exit.
- GOTCHA: relaunching with `nohup … & disown` from the Bash tool produced a
  **wedged** process (RSS ~32KB, zero log output, never bound the port) — the
  detached launch didn't take. Fix: relaunch with the Bash tool's
  `run_in_background: true` instead; it came up cleanly (logs flowing, bound
  :8800). Caveat: that process is tied to the session. For a persistent daemon
  the user should relaunch it from their own terminal.
- `DOCKER_HOST` is empty in the tool's shell — must export it before launching.
- Dashboard templates are `go:embed`, so any template/handler change needs a
  daemon restart onto the freshly `make build`-ed binary to take effect.

## Local validators
- `python3` on this host is Homebrew's and has no PyYAML; the validators
  (`validate-manifests.py`, `validate-registry.py`) need `/usr/bin/python3`.
- Never pipe a verification step into `tail`/`head` inside an `&&` chain: the
  pipeline's exit status is the last command's, so a crashing validator still
  lets the chain (and a push) continue. Run it unpiped, or `setopt pipefail`.

## Image namespace: trust the workflow, not the docs
- CLAUDE.md said registry images live under `ghcr.io/alexgoller/`, but
  `.github/workflows/plugins.yaml` pushes to `${{ github.repository_owner }}` =
  `illumio-community`. I copied the stale doc into a new registry entry. For
  anything CI-produced (image names, tags, paths) read the workflow first and fix
  the doc when they disagree.
- New GHCR packages in the illumio-community org are private by default; a
  freshly built plugin image is not installable until an org owner makes it
  public in the package settings UI (no API). Probe anonymously:
  `https://ghcr.io/token?scope=repository:<owner>/<image>:pull` then
  `GET /v2/<owner>/<image>/manifests/<tag>` — 200 public, 401 private, 403 absent.

## Releases with GoReleaser (learned the hard way on v0.15.7/8)
- GoReleaser does NOT overwrite existing release assets: a re-run of a tag's release
  dies with 422 already_exists unless `release.replace_existing_artifacts: true`.
  Keep that set so a release can be re-run after fixing a secret.
- Validate with the SAME GoReleaser version CI uses (goreleaser-action `~> v2` =
  latest); an older local binary misses deprecations (brews -> homebrew_casks,
  binary -> binaries, hooks.post.install -> install_steps).
- A tap push from CI needs a token that can write to the tap repo: a fine-grained
  PAT must have the ORG as resource owner (and may need org approval); a classic
  `repo` token just works. 403 "Resource not accessible by personal access token"
  = wrong token, not wrong pipeline.
- `gh secret set NAME` with no --body reads stdin; under the `!` runner there is
  no TTY, so it silently stores an EMPTY value (`gh secret list` still shows it).
  Set secrets in the GitHub UI or with --body "$(pbpaste)".
- Moving a published tag is blocked by the classifier (destructive git); cutting
  the next patch version is the non-destructive path.

## PCE API: verify field names against the live PCE before coding
- Label usage flags come from `GET /labels?usage=true` (an 18-key `usage`
  block). `representation=label_usage` returns 200 but NO usage block — a
  subagent's confident guess. A key-names-only probe (never print values)
  against the real PCE is cheap and beat guessing; do it for any new endpoint.
- Rulesets carry both `rules` and `deny_rules`; rules/boundaries use
  `consumers`/`providers`/`ingress_services`; actors are `{label|label_group|
  ip_list|workload: {href}}` or `{actors: "ams"}`.

## "It's missing on the dashboard" — check which dashboard
- The access badge commit (d235bdb) only touched the PORTAL; the plugger web
  dashboard never rendered it, and plugins.json had no `access` at all because
  `bin/plugger` was built before the field existed. When a feature spans
  portal + dashboard + stored state, verify all three, and rebuild `bin/` right
  after a manifest-struct change — installs made with a stale binary silently
  drop new fields (hence the registry fallback).

## zsh: never use `path` as a loop variable
- `for path in / /config` sets $PATH (zsh ties `path` to PATH) → every command
  in the loop body fails with "command not found: curl". Use `pg`, `url`, etc.
