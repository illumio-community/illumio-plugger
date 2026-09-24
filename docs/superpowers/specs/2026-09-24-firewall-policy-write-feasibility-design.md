# Firewall Policy Write-Back — Feasibility & Design Decision

**Status:** Draft for review
**Date:** 2026-09-24
**Author:** Alex Goller (with Claude Opus 4.8)
**Deliverable:** Decision doc + Check Point validation-pilot plan. **No firewall code is built by this document.**

---

## 1. Problem & motivation

Customers increasingly ask Illumio/Plugger to **write into firewall policy**, not just read
and calculate it. Today Plugger already:

- **Computes** label-based policy down to concrete rules — `policy-resolver` turns abstract
  ruleset scopes into `srcIP → dstIP : port/proto : action`.
- **Writes membership** to firewalls — `palo-alto-dag-sync` pushes IP→tag mappings into
  PAN-OS Dynamic Address Groups; `fortigate-sync` pushes IPs into RSSO groups / address
  objects. Humans author the *rules* once; those rules reference the dynamic groups, so
  membership churns without touching the rulebase.

The new ask is a step up in **risk class**: authoring the actual **rules** (the enforcement
policy), keeping them **continuously reconciled** against Illumio state, across multiple
firewall vendors. This document assesses feasibility, recommends an architecture, and
defines a depth-first pilot to de-risk before broad investment.

### Scope decisions (confirmed with stakeholder)

- **Write scope:** support **both** a *managed-block rule model* (engine owns a delimited
  rule section that references dynamic groups) **and** an *IP-literal rule model*
  (rules carry resolved IPs), **config-selectable per firewall**.
- **Delivery mechanism:** support **both** a **GitOps/Terraform** backend and a
  **direct-API** backend, chosen **per vendor/deployment**.
- **Continuous reconciliation (required):** the engine must continually watch the Illumio
  rulebase **and** workload/label changes and converge the firewall to desired state —
  **event-driven where possible**, with a periodic full reconcile as a safety net.
- **Target platforms:** **Check Point, Palo Alto, Fortinet.** (Cisco FMC dropped as out of
  scope.) "Other enforcement points welcome" is handled by the vendor-adapter interface.

---

## 2. Recommendation summary

1. **Build a spin-off engine repo** (working name **`illumio-policy-enforcer`**), not a set
   of in-repo Plugger plugins. Rule-writing is a different risk/RBAC/audit class than
   Plugger's read-mostly plugins and needs Terraform/CI machinery, independent release
   cadence, and standalone (non-Plugger) consumers. **Plugger remains the control surface:**
   `policy-resolver` produces computed intent; a thin `fw-enforcer` plugin drives the engine,
   renders dry-run diffs, and routes approvals through the existing reporting bus.
2. **Model enforcement as a two-speed reconciler** (see §4.4). This falls directly out of a
   convergent finding across all three vendors (§5): each separates **membership churn**
   (a commit/deploy-free dynamic-object channel) from **structural rule change**
   (a gated commit/install/publish channel). Route the two accordingly.
3. **Pilot Check Point first.** Its ordered-layer + permission-scoped API admin gives a
   **provable** isolation guarantee (a bug cannot reach human rules), and its
   `session → publish → install-policy` model is the cleanest atomic primitive of the three.
4. **P1 is dry-run-only.** Prove the compute → plan → diff round-trip before any write path.

---

## 3. What exists today (build on, don't duplicate)

| Component | Role | Reuse in enforcer |
|---|---|---|
| `policy-resolver` | Resolves label policy → concrete `src/dst/service/action` rules | **Source of desired intent.** Stays in Plugger. |
| `palo-alto-dag-sync` | Pushes IP→tag membership to PAN-OS DAGs (User-ID API) | Becomes the **PAN membership channel** of the reconciler. |
| `fortigate-sync` | Pushes IPs to FortiGate RSSO / address objects | Becomes the **Forti membership channel**. |
| `pce-events` | PCE event stream / webhook consumer | **Event source** for the reconciler. |
| Reporting/output bus (Slack/Teams/email/webhook) | Routed notifications | **Approval-gate + audit channel.** |
| `policy-diff`, `policy-backup` | Change tracking / snapshots | Drift baseline + rollback reference material. |

The enforcer **consumes** these; it does not reimplement policy computation or membership sync.

---

## 4. Architecture

### 4.1 Intent layer (`DesiredPolicy`)

A canonical, vendor-agnostic desired-state model derived deterministically from
`policy-resolver` output:

```
Rule {
  owner_tag        # e.g. "illumio-enforcer" — provenance/ownership marker
  source           # set-ref (dynamic group) OR resolved IPs (literal mode)
  destination      # set-ref OR resolved IPs
  service          # port/proto set
  action           # allow | deny
  position_hint    # relative anchor within the engine's owned section
  intent_id        # stable key for idempotent reconcile (maps to vendor UID)
}
```

Everything downstream is a pure function of `DesiredPolicy`. This makes dry-run, diffing,
and drift detection deterministic and testable without a live firewall.

### 4.2 Rule-model strategy (pluggable, per firewall)

- **`managed-block`** (default, recommended) — rules reference **dynamic groups** the
  membership channel maintains; the engine writes only its **owned rule section**. Lowest
  churn on the rulebase, smallest blast radius.
- **`ip-literal`** — rules carry resolved IPs straight from `policy-resolver`. Highest
  fidelity, highest churn; used where dynamic-group indirection isn't available or wanted.

### 4.3 Delivery backend (pluggable, per vendor/deployment)

- **`gitops`** — render vendor Terraform/native config into a Git repo → PR → `plan`/diff →
  human approve → CI applies. Plan-preview, review, audit trail, and rollback (git revert)
  come for free. Preferred where the customer already runs IaC.
- **`direct-api`** — a vendor adapter commits via the management API using that vendor's
  atomic primitive. Real-time, no external CI dependency; the engine owns the safety
  machinery itself.

### 4.4 Reconciler — two-speed control loop (core)

A continuous desired-vs-observed loop (Kubernetes-style):

```
        Illumio (PCE)                              Firewall
   ┌───────────────────┐                     ┌──────────────────┐
   │ workloads / labels │──(events)──┐        │  dynamic objects  │
   │ rulesets / rules   │──(events)──┤        │  (membership)     │
   └───────────────────┘            │        │  owned rule block │
                                    ▼        └──────────────────┘
                          ┌──────────────────┐        ▲   ▲
                          │  Reconciler       │        │   │
                          │  desired = f(PCE) │        │   │
                          │  observed = Read  │────────┘   │
                          │  diff → ChangeSet │            │
                          └──────────────────┘            │
                             │            │               │
             ┌───────────────┘            └───────────────┘
             ▼ FAST path                       ▼ SLOW path
   membership change (workload/label churn)   structural change (ruleset/service/scope)
   → dynamic-object channel                   → rule authoring
   → NO commit/install/publish                → gated: dry-run → approve → commit/install
   → real-time, high-frequency, low-risk      → rare, rollback token, blast-radius limits
```

- **Fast path (membership):** workload/label events → update dynamic-group membership via
  the vendor's commit-free channel. This is what the existing sync plugins already do; the
  reconciler generalizes it. High-frequency, event-driven, minimal risk.
- **Slow path (structural):** rulebase changes (new/edited/removed rules, services, scopes)
  → author rules in the engine's owned section → dry-run → approval gate → vendor commit/
  install/publish → rollback token recorded. Rare and gated.
- **Event-driven + periodic safety net:** subscribe to PCE events via `pce-events`; also run
  a **periodic full reconcile** (default 1h) so the system converges even if an event is
  missed. Convergence is idempotent — replaying is safe.

### 4.5 Vendor adapter interface

```
Adapter {
  Plan(desired DesiredPolicy) -> ChangeSet          # compute diff vs ReadState()
  Apply(changeset ChangeSet)  -> ApplyResult{token} # commit via vendor atomic primitive
  Rollback(token)             -> error              # restore prior state
  ReadState()                 -> ObservedPolicy     # owned section + membership
  UpdateMembership(delta)     -> error              # fast-path, commit-free channel
}
```

Each adapter maps canonical intent to vendor objects and **owns its vendor's atomicity
primitive** (§5).

### 4.6 Safety core (mandatory, vendor-independent)

Non-negotiable guarantees enforced above every adapter:

1. **Ownership confinement** — the engine only ever touches rules it authored (owned
   layer/section + `owner_tag` + stored `intent_id`↔UID ledger). Where the vendor supports
   it, back this with a **permission-scoped API admin** so it's a hard guarantee, not a
   convention (Check Point ordered layer + scoped admin; PAN pre/post-rulebase + device-group).
2. **Dry-run/plan always** — every structural change produces a diff first; nothing applies
   without a plan.
3. **Approval gate** — structural changes route through the Plugger reporting bus
   (Slack/Teams/email) for explicit human approval before apply. Configurable auto-approve
   only for the fast/membership path.
4. **Drift detection** — `ReadState` vs `DesiredPolicy` on every reconcile; out-of-band edits
   surface as drift (reported, not silently reverted, unless configured).
5. **Rollback token per apply** — each structural apply records how to revert (vendor
   revision/session/ADOM revision, or git revert for GitOps).
6. **Rate-limit / circuit-breaker** — a label storm can never hammer a firewall; bound
   change velocity and trip a breaker on repeated apply failures.
7. **Managed-scope boundary** — a hard assertion that a computed ChangeSet references only
   owned objects; a ChangeSet that would touch a non-owned rule is rejected, not applied.

---

## 5. Per-vendor feasibility matrix (grounded, 2025–2026)

All three targets are **GREEN** for automated rule authorship. Sources are vendor docs and
Terraform registries captured during research (2026-09-24); version-specific items flagged
**verify** must be confirmed against the deployed build.

| | Rule CRUD + reorder | Atomic primitive (best) | Isolation | Commit-free membership channel | Terraform (rules) |
|---|---|---|---|---|---|
| **Check Point** 🟢 | Mgmt API `add`/`set`/`delete-access-rule`; reorder via `set-access-rule new-position` | **Session = transaction:** `login → edit → publish → install-policy`; `discard` = clean rollback; every publish = DB revision | **Ordered layer + permission-scoped API admin = hard guarantee**; sections; rule UID; `custom_fields` tags | **Generic Data Center objects** (JSON feed) — enforced on gateways with **no install-policy** | `checkpoint_management_access_rule`; `publish`/`install_policy` out-of-band resources |
| **Palo Alto** 🟢 | REST `Policies/SecurityRules` CRUD + `:move` (`where` top/bottom/before/after) | Candidate config → **`commit --partial <admin>`** (only the automation admin's changes) → Panorama **push**; config/commit locks; config revisions | Panorama **device-group** + **pre/post-rulebase** + persistent **rule UUID**; rule tags; audit comment | **DAG + User-ID `register`/`unregister`** — updates membership **without commit** | `panos_security_policy_rules` (manages a **subset** ✓); provider does **not** commit — separate step |
| **Fortinet** 🟢 | FMG JSON-RPC `add`/`set`/`move`/`delete` on `.../pkg/<pkg>/firewall/policy`; FortiOS REST CMDB | ADOM **workspace lock → commit → unlock → `securityconsole/install/package`** (preview first); ADOM **revisions** for rollback | policyid range + **`global-label` section** + **Policy Blocks**; per-policy comments (convention; RBAC at ADOM/pkg level) | **Dynamic address** (FSSO/RSSO/SDN connectors) — membership pushed live, **install-independent** | `fortimanager_packages_firewall_policy` + `securityconsole_install_package` (`auto_lock_ws`); **weak on relative ordering** |

### Cross-vendor insight (drives §4.4)

Every vendor **separates membership from structure**: a dynamic-object channel that updates
enforced IP sets **without** the commit/install/publish step (CP Generic Data Center objects,
PAN DAG/User-ID, Forti FSSO/SDN dynamic address), versus rule authoring that **requires** the
gated commit/install/publish. The reconciler must route these two change classes to two
different mechanisms — this is the single most important design consequence of the research.

### Common gotchas (all vendors)

- **"Committed/published" ≠ "enforced."** Every vendor stages then activates (publish +
  install-policy / partial-commit + push / commit + install). Model apply as async;
  poll to confirmation.
- **Ordering is fragile.** Anchor to a stable owned **section marker** and key rules by
  **UID/UUID**, never by name or absolute index. Terraform parallelism reorders
  unpredictably on all three — prefer direct-API `move` for ordering-sensitive work.
- **Isolation must be enforced where possible.** Prefer a dedicated layer/DG/section **plus a
  permission-scoped API admin**; treat comment/tag-only isolation as convention and reconcile
  strictly by `owner_tag`.
- **Membership vs rule mental models must not mix.** "Rule is there but matches nothing"
  bugs come from editing a group that needs commit/install vs a dynamic object that doesn't.

---

## 6. Risk model

| Risk | Severity | Mitigation |
|---|---|---|
| Engine edits/deletes a human-authored rule | **Critical** | Ownership confinement + permission-scoped API admin + managed-scope boundary assertion (§4.6). Pilot success criterion #1. |
| Bad rule black-holes production traffic | **Critical** | Dry-run + approval gate + preview-before-install; rollback token; start visibility/allow-only; blast-radius limits. |
| Membership storm hammers the firewall | High | Fast-path uses commit-free channel; rate-limit + circuit-breaker; batch. |
| Drift from out-of-band admin edits | High | Drift detection every reconcile; report-don't-revert by default; reconcile only owned objects. |
| "Published but not enforced" gap | Medium | Async apply model with confirmation polling; alert if publish succeeds but install fails. |
| Terraform ordering/state drift | Medium | Use subset resources; direct-API for ordering-sensitive changes; isolate engine rules in their own layer/policy. |
| Secret sprawl (mgmt creds) | Medium | Plugger secret handling (env-name refs, masked); per-vendor scoped API admin, least privilege. |
| Multi-domain blast radius (MDS/Panorama/ADOM) | Medium | Scope engine to a single domain/DG/ADOM unless global is explicitly intended. |

---

## 7. Spin-off rationale

**Recommend a separate repo** (`illumio-policy-enforcer`), because:

- **Risk/RBAC/audit class** — rule-writing needs stronger auth, approval, and audit than
  Plugger's read-mostly plugin model provides.
- **Tooling** — it needs Terraform providers + CI/CD (plan/apply pipelines) that Plugger
  doesn't carry.
- **Release cadence** — enforcement changes shouldn't be coupled to Plugger releases.
- **Standalone value** — usable by customers who compute intent another way, not only via
  Plugger.

**Integration:** `policy-resolver` (Plugger) emits desired intent → a thin `fw-enforcer`
Plugger plugin invokes the engine, shows dry-run diffs in its dashboard, and routes approvals
through the reporting bus. Clean separation: **compute in Plugger, enforce in the engine.**

### Repo boundary

**Stays in `illumio-plugger`:** `policy-resolver` (emits intent), the existing membership
sync plugins `palo-alto-dag-sync` / `fortigate-sync` (fast-path; their vendor-client code is
extracted into the engine as a shared library in a later phase), `pce-events` (event source),
the reporting/output bus (approval + audit), and a **new thin `fw-enforcer` plugin** — the
control surface that invokes the engine, renders dry-run diffs, and routes approvals.

**Goes into `illumio-policy-enforcer`:** the engine core (`DesiredPolicy` model, two-speed
reconciler, diff/plan, drift detection), rule-model strategies, delivery backends (gitops +
direct-api), vendor adapters (checkpoint/panos/fortimanager), the safety core, per-vendor
Terraform modules, CI/CD plan-apply pipelines, and the engine's tests.

**The seam:** `policy-resolver` emits **`DesiredPolicy` as a versioned JSON schema**; the
engine consumes it. That single contract is the entire API boundary — testable on both sides
and consumable by non-Plugger users. The engine ships as a **Go module + CLI + container
image**, so both the `fw-enforcer` plugin and standalone CI can drive it.

---

## 8. Phasing

- **P0 — this deliverable.** Decision doc + Check Point pilot plan. No firewall code.
- **P1 — prove the round-trip (dry-run only).** Engine skeleton + `DesiredPolicy` from
  `policy-resolver` + Check Point adapter, `managed-block` model, `gitops` backend,
  **plan/diff only, no writes.** Exit: dry-run plan matches lab firewall reality.
- **P2 — write path on Check Point.** `direct-api` apply + rollback; approval gate via
  Plugger bus; the two-speed reconciler (event via `pce-events` + periodic full reconcile).
- **P3 — second vendor (Palo Alto).** Reuse `palo-alto-dag-sync` as the membership channel;
  add the rule-authoring slow path. Validates the adapter abstraction.
- **P4 — breadth + depth.** Fortinet adapter; `ip-literal` model; GA hardening
  (rate limits, drift dashboards, multi-domain scoping, docs).

---

## 9. Check Point validation pilot (depth-first)

**Goal:** prove the full compute → plan → (guarded) write → rollback round-trip on one vendor
before committing to the broader build, and confirm provable rule isolation.

**Lab setup:**
- Check Point Management server (R81+, eval/CloudGuard acceptable) + one test Security Gateway.
- A **dedicated ordered layer** (or dedicated policy package) that the engine fully owns.
- A **permission-scoped API admin** whose profile can write **only** that layer.
- A handful of representative Illumio rulesets on ag-demo-snc (or a lab PCE) to resolve.

**Round-trip to prove:**
1. `policy-resolver` intent → Check Point adapter `Plan()` → dry-run diff.
2. `login` (session) → `add-access-rule` into the **owned layer only** → `publish` →
   `install-policy` → verify enforced → `Rollback()` (session discard pre-publish; revision/
   known-good package post-publish).
3. Render the **same** intent as Check Point Terraform (`checkpoint_management_access_rule`)
   and **diff API-backend vs GitOps-backend** output for equivalence.
4. Exercise the **fast path**: update a **Generic Data Center object** feed and confirm
   membership changes enforce **without** install-policy.

**Success criteria (all must hold):**
1. **Provable confinement** — writes land only in the owned layer; attempts to touch any
   other rule are rejected by the managed-scope assertion and blocked by the scoped admin.
2. **Plan fidelity** — the dry-run plan equals the applied result (no surprise changes).
3. **Rollback** — a published change can be reverted to the prior known-good state.
4. **Backend equivalence** — `direct-api` and `gitops` produce an equivalent owned rulebase.
5. **Commit-free membership** — Generic Data Center feed updates enforce without install-policy.

**Explicitly de-risk during the pilot:** rule ordering/position semantics, `publish` vs
`install-policy` timing, concurrent-admin session conflicts/locks, the R81 login-frequency
rate limit, and MDS/domain scoping.

---

## 10. Open questions / verify before/at pilot

- **Rollback API surface (Check Point):** confirm whether a stable *public* API verb exists to
  revert to an arbitrary DB revision, or whether rollback is session-discard (pre-publish) +
  known-good policy re-install (post-publish) only. **verify**
- **CP login-frequency rate limit** exact numbers + tuning knob (`mgmt_cli set api-settings`).
  **verify**
- **PAN partial-commit** reliability under an automation admin + interaction with commit locks
  when human admins have pending edits. **verify**
- **Fortinet** per-package vs per-ADOM workspace-lock granularity and Policy-Block ordering
  semantics on the target FMG build. **verify**
- **Approval-gate UX:** what does a firewall-rule approval look like in the Plugger reporting
  bus (Slack/Teams) — diff rendering, approve/deny, timeout behavior?
- **Repo/ownership:** confirm `illumio-policy-enforcer` repo name, license, and whether the
  membership channels physically move out of the existing sync plugins or are wrapped.

---

## Appendix — key source references

- **Check Point:** Management API reference `sc1.checkpoint.com/documents/latest/APIs/`;
  Managing Security through API, Session Flow, Database Revisions, Generic Data Center
  Objects, Updatable Objects (R81 admin guides); Terraform `CheckPointSW/checkpoint`
  (`access_rule`, `install_policy`).
- **Palo Alto:** PAN-OS/Panorama REST & XML API (`docs.paloaltonetworks.com`); User-ID / DAG
  register-IP; selective/partial commit; Terraform `PaloAltoNetworks/panos`
  (`security_policy_rules`).
- **Fortinet:** FortiManager JSON-RPC policy package mgmt; `securityconsole/install`;
  config-transaction (FortiOS 7.4.1+); FSSO/SDN dynamic address; Terraform
  `fortinetdev/fortimanager` (`packages_firewall_policy`, `securityconsole_install_package`).

*(Full URL list captured in the research phase; re-verify version-specific paths against the
deployed builds.)*
