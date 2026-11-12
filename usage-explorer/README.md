# Usage Explorer

> **Status: Preview** — functional against a live PCE, needs wider real-world validation. Read-only: it never writes to the PCE.

Where and how every policy object is used. Pick any **label, label group,
service or IP list** and see every place it is referenced — not just "in use /
not in use", but which workloads carry it, which rulesets reference it and at
which **rule number**, in what role, in draft and/or active policy, plus
enforcement boundaries, pairing profiles, label groups and everything else the
PCE reports. Objects nothing references are flagged **unused** — cleanup
candidates you can hand to the policy team.

## Install

```
plugger install usage-explorer
```

## What you get per object

| Section | Labels | Label groups | Services | IP lists |
|---|---|---|---|---|
| **Workloads** — exact count + sample, enforcement mode, linked to the PCE | ✓ | | | |
| **Rules** — ruleset, rule **#**, how (ruleset scope / source / destination / service), allow or **deny**, extra-scope, disabled, draft/active | ✓ | ✓ | ✓ | ✓ |
| **Enforcement boundaries** — name, role, draft/active | ✓ | ✓ | ✓ | ✓ |
| **Label groups** — groups containing the label (or parent groups) | ✓ | ✓ | | |
| **Pairing profiles** | ✓ | | | |
| **Other references** — virtual services, container workload profiles, RBAC permission scopes, label mapping rules, ... (from the PCE's own label usage flags) | ✓ | | | |
| **Status** — in use / **unused** / draft only / pending delete / missing | ✓ | ✓ | ✓ | ✓ |

Everything links to the PCE console. The **Top Impact** tab ranks objects by
workloads + rule references — the ones where a change has the biggest blast
radius.

### About rule numbers

Illumio rules have no stable human-readable number. The `#` shown is the rule's
position within its ruleset (1-based), the same order the PCE console lists
them in. If a rule sits at a different position in draft than in active, both
are shown (`#3 (draft #4)`). Deny rules are numbered within the ruleset's deny
rule list.

### About "unused"

An object is unused when this plugin finds no workload, rule, ruleset scope,
boundary, label group or pairing profile referencing it **and** the PCE's own
usage flags for it are all clear. The PCE's flags win: if the PCE says a label
is used by a virtual service, it is not reported as unused even though this
plugin does not resolve virtual services in detail. Always confirm in the PCE
before deleting anything.

**Draft only** = created in draft, not yet provisioned. **Pending delete** =
exists in active policy but has been removed from draft. **Missing** = a rule
references an href that is not in the fetched catalog (deleted object, or a
policy version that is not indexed).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL` | `3600` | Seconds between index rebuilds (the dashboard has a Rebuild button too) |
| `INCLUDE_DRAFT` | `true` | Index draft policy as well as active |
| `WORKLOAD_SAMPLE` | `50` | Workloads listed per label in the detail view (the count is always exact) |
| `PCE_TLS_SKIP_VERIFY` | `true` | Skip TLS verification for the PCE |

PCE credentials are injected by plugger. The plugin only issues `GET` requests.

## PCE calls per rebuild

`/labels?usage=true`, `/workloads`, `/pairing_profiles`, and for each indexed
policy version `/sec_policy/{version}/{rule_sets, enforcement_boundaries,
label_groups, ip_lists, services}` — about 13 requests per rebuild with draft
enabled, `max_results=10000` each. Very large PCEs (more than 10 000 workloads
or labels) are truncated at that limit for now.

## API

| Endpoint | Description |
|---|---|
| `GET /api/usage` | Full index: counts, top impact, every object with its references |
| `GET /api/summary` | Counts and metadata without the object list |
| `GET /api/object?id=<id>` | One object (`id` is the href with the policy version stripped) |
| `GET /api/unused` | Just the unused objects — handy for cleanup scripts |
| `POST /api/rebuild` | Trigger a rebuild now |
| `GET /healthz` | Health |

## Reports

Publishes a report on the plugger reporting bus (tags `usage`, `hygiene`)
whenever the number of unused objects changes, with the per-kind breakdown and
the first 20 unused objects.
