# Check Point Dry-Run Pilot (P1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove the compute → plan → diff round-trip for firewall rule authoring against Check Point, dry-run only (no writes), in the new `illumio-policy-enforcer` engine.

**Architecture:** A Go engine consumes a versioned `DesiredPolicy` JSON (produced by Plugger's `policy-resolver`), reads the *owned* rule section from a Check Point Management server, computes a vendor-agnostic `ChangeSet` (managed-block model), and can also render the same intent as Check Point Terraform. Everything is a pure function of `DesiredPolicy` + `ObservedPolicy`, so all logic is testable against recorded API fixtures; only the final validation task needs a live lab.

**Tech Stack:** Go 1.23+, standard library `net/http` + `net/http/httptest` for the Check Point Management Web API, `encoding/json`, Go's built-in `testing`. No third-party deps in P1 except `gopkg.in/yaml.v3` for the run config. Terraform rendering is plain text templating (`text/template`); no Terraform execution in P1.

**Spec:** `docs/superpowers/specs/2026-09-24-firewall-policy-write-feasibility-design.md`

## Global Constraints

- **New repo:** `illumio-policy-enforcer`. This plan creates it from empty. Paths below are relative to that repo root.
- **Dry-run only:** P1 performs **no** write calls to any firewall. The Check Point client implements `login`, `logout`, and `show-access-rulebase` only. `add/set/delete-access-rule`, `publish`, `install-policy` are **out of scope for P1** and must not be called.
- **Ownership confinement is mandatory:** the engine only ever considers rules in its **owned layer** carrying its `owner_tag` (Check Point `custom-fields.field_1`). A `ChangeSet` that references a non-owned rule is a bug and must be rejected by `safety.AssertOwned`.
- **Go module path:** `github.com/alexgoller/illumio-policy-enforcer`.
- **Managed-block model only** in P1 (rules reference dynamic groups by name; `ip-literal` is a later phase).
- **Determinism:** `plan.Diff` output ordering must be stable (sort changes by `IntentID`) so golden-file tests and dry-run diffs are reproducible.
- **Secrets:** Check Point credentials come from env (`CP_MGMT_HOST`, `CP_MGMT_USER`, `CP_MGMT_PASSWORD`, `CP_MGMT_API_KEY`) or the run-config referencing env var *names*, never literals in code or fixtures.

---

### Task 1: Repo scaffold + CI

**Files:**
- Create: `go.mod`
- Create: `cmd/enforcer/main.go`
- Create: `.github/workflows/ci.yml`
- Create: `testdata/.gitkeep`
- Create: `README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: module `github.com/alexgoller/illumio-policy-enforcer`; a buildable `enforcer` binary stub.

- [ ] **Step 1: Initialize the module**

```bash
mkdir -p illumio-policy-enforcer && cd illumio-policy-enforcer
go mod init github.com/alexgoller/illumio-policy-enforcer
mkdir -p cmd/enforcer testdata
touch testdata/.gitkeep
```

- [ ] **Step 2: Write the CLI stub**

`cmd/enforcer/main.go`:

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: enforcer <plan> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "plan":
		// wired up in Task 8
		fmt.Fprintln(os.Stderr, "plan: not yet implemented")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}
```

- [ ] **Step 3: Add CI**

`.github/workflows/ci.yml`:

```yaml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.23' }
      - run: go vet ./...
      - run: go build ./...
      - run: go test ./... -v
```

- [ ] **Step 4: Verify it builds**

Run: `go build ./... && go vet ./...`
Expected: no output, exit 0.

- [ ] **Step 5: Commit**

```bash
git init && git add -A
git commit -m "chore: scaffold illumio-policy-enforcer module + CI"
```

---

### Task 2: DesiredPolicy intent schema (load + validate)

**Files:**
- Create: `internal/intent/desiredpolicy.go`
- Test: `internal/intent/desiredpolicy_test.go`
- Create: `testdata/desired_basic.json`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type DesiredPolicy struct { SchemaVersion string; OwnerTag string; Layer string; Rules []DesiredRule }`
  - `type DesiredRule struct { IntentID, Name string; Sources, Destinations, Services []string; Action string; Position int }`
  - `func Load(r io.Reader) (DesiredPolicy, error)` — decodes JSON and calls `Validate`.
  - `func (p DesiredPolicy) Validate() error`.
  - Action constants: `ActionAllow = "allow"`, `ActionDeny = "deny"`.

- [ ] **Step 1: Write the failing test**

`internal/intent/desiredpolicy_test.go`:

```go
package intent

import (
	"strings"
	"testing"
)

func TestLoadValid(t *testing.T) {
	in := `{"schema_version":"1.0","owner_tag":"illumio-enforcer","layer":"Illumio-Managed",
	"rules":[{"intent_id":"r1","name":"web-to-db","sources":["grp-web"],
	"destinations":["grp-db"],"services":["tcp/5432"],"action":"allow","position":1}]}`
	p, err := Load(strings.NewReader(in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.OwnerTag != "illumio-enforcer" || len(p.Rules) != 1 || p.Rules[0].IntentID != "r1" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestValidateRejectsBadAction(t *testing.T) {
	in := `{"schema_version":"1.0","owner_tag":"x","layer":"L",
	"rules":[{"intent_id":"r1","name":"n","action":"maybe","position":1}]}`
	if _, err := Load(strings.NewReader(in)); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestValidateRejectsDuplicateIntentID(t *testing.T) {
	in := `{"schema_version":"1.0","owner_tag":"x","layer":"L","rules":[
	{"intent_id":"dup","name":"a","action":"allow","position":1},
	{"intent_id":"dup","name":"b","action":"allow","position":2}]}`
	if _, err := Load(strings.NewReader(in)); err == nil {
		t.Fatal("expected error for duplicate intent_id")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/intent/ -run TestLoad -v`
Expected: FAIL — `undefined: Load`.

- [ ] **Step 3: Write minimal implementation**

`internal/intent/desiredpolicy.go`:

```go
package intent

import (
	"encoding/json"
	"fmt"
	"io"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

type DesiredRule struct {
	IntentID     string   `json:"intent_id"`
	Name         string   `json:"name"`
	Sources      []string `json:"sources"`
	Destinations []string `json:"destinations"`
	Services     []string `json:"services"`
	Action       string   `json:"action"`
	Position     int      `json:"position"`
}

type DesiredPolicy struct {
	SchemaVersion string        `json:"schema_version"`
	OwnerTag      string        `json:"owner_tag"`
	Layer         string        `json:"layer"`
	Rules         []DesiredRule `json:"rules"`
}

func Load(r io.Reader) (DesiredPolicy, error) {
	var p DesiredPolicy
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return DesiredPolicy{}, fmt.Errorf("decode desired policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return DesiredPolicy{}, err
	}
	return p, nil
}

func (p DesiredPolicy) Validate() error {
	if p.OwnerTag == "" {
		return fmt.Errorf("owner_tag is required")
	}
	if p.Layer == "" {
		return fmt.Errorf("layer is required")
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		if r.IntentID == "" {
			return fmt.Errorf("rule %d: intent_id is required", i)
		}
		if seen[r.IntentID] {
			return fmt.Errorf("duplicate intent_id %q", r.IntentID)
		}
		seen[r.IntentID] = true
		if r.Action != ActionAllow && r.Action != ActionDeny {
			return fmt.Errorf("rule %q: invalid action %q", r.IntentID, r.Action)
		}
	}
	return nil
}
```

- [ ] **Step 4: Create the sample fixture**

`testdata/desired_basic.json`:

```json
{
  "schema_version": "1.0",
  "owner_tag": "illumio-enforcer",
  "layer": "Illumio-Managed",
  "rules": [
    {"intent_id": "web-db", "name": "web-to-db", "sources": ["grp-web"],
     "destinations": ["grp-db"], "services": ["tcp/5432"], "action": "allow", "position": 1},
    {"intent_id": "app-cache", "name": "app-to-cache", "sources": ["grp-app"],
     "destinations": ["grp-cache"], "services": ["tcp/6379"], "action": "allow", "position": 2}
  ]
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/intent/ -v`
Expected: PASS (all three).

- [ ] **Step 6: Commit**

```bash
git add internal/intent testdata/desired_basic.json
git commit -m "feat(intent): DesiredPolicy schema with load + validation"
```

---

### Task 3: Core model types + vendor-agnostic diff (managed-block)

**Files:**
- Create: `internal/model/model.go`
- Create: `internal/plan/diff.go`
- Test: `internal/plan/diff_test.go`

**Interfaces:**
- Consumes: `intent.DesiredPolicy`, `intent.DesiredRule`.
- Produces:
  - `model.ObservedRule struct { UID, IntentID, Name string; Sources, Destinations, Services []string; Action string; Position int }`
  - `model.ObservedPolicy struct { OwnerTag, Layer string; Rules []ObservedRule }`
  - `model.ChangeOp` with consts `OpCreate, OpUpdate, OpDelete, OpMove`.
  - `model.Change struct { Op ChangeOp; IntentID, UID, Reason string; Desired *intent.DesiredRule }`
  - `model.ChangeSet struct { OwnerTag, Layer string; Changes []Change }`
  - `func plan.Diff(d intent.DesiredPolicy, o model.ObservedPolicy) model.ChangeSet`.

- [ ] **Step 1: Write the model types**

`internal/model/model.go`:

```go
package model

import "github.com/alexgoller/illumio-policy-enforcer/internal/intent"

type ObservedRule struct {
	UID          string
	IntentID     string // "" means "not authored by the engine" (foreign rule)
	Name         string
	Sources      []string
	Destinations []string
	Services     []string
	Action       string
	Position     int
}

type ObservedPolicy struct {
	OwnerTag string
	Layer    string
	Rules    []ObservedRule
}

type ChangeOp string

const (
	OpCreate ChangeOp = "create"
	OpUpdate ChangeOp = "update"
	OpDelete ChangeOp = "delete"
	OpMove   ChangeOp = "move"
)

type Change struct {
	Op       ChangeOp
	IntentID string
	UID      string // set for update/delete/move (identifies the existing rule)
	Reason   string
	Desired  *intent.DesiredRule // set for create/update/move
}

type ChangeSet struct {
	OwnerTag string
	Layer    string
	Changes  []Change
}
```

- [ ] **Step 2: Write the failing diff test**

`internal/plan/diff_test.go`:

```go
package plan

import (
	"testing"

	"github.com/alexgoller/illumio-policy-enforcer/internal/intent"
	"github.com/alexgoller/illumio-policy-enforcer/internal/model"
)

func desired(rules ...intent.DesiredRule) intent.DesiredPolicy {
	return intent.DesiredPolicy{OwnerTag: "illumio-enforcer", Layer: "L", Rules: rules}
}

func TestDiffCreatesMissingRule(t *testing.T) {
	d := desired(intent.DesiredRule{IntentID: "r1", Name: "n1", Action: "allow", Position: 1})
	o := model.ObservedPolicy{OwnerTag: "illumio-enforcer", Layer: "L"}
	cs := Diff(d, o)
	if len(cs.Changes) != 1 || cs.Changes[0].Op != model.OpCreate || cs.Changes[0].IntentID != "r1" {
		t.Fatalf("expected one create for r1, got %+v", cs.Changes)
	}
}

func TestDiffDeletesOwnedRuleNotInDesired(t *testing.T) {
	d := desired() // empty
	o := model.ObservedPolicy{OwnerTag: "illumio-enforcer", Layer: "L", Rules: []model.ObservedRule{
		{UID: "uid-1", IntentID: "old", Name: "gone", Action: "allow", Position: 1},
	}}
	cs := Diff(d, o)
	if len(cs.Changes) != 1 || cs.Changes[0].Op != model.OpDelete || cs.Changes[0].UID != "uid-1" {
		t.Fatalf("expected one delete of uid-1, got %+v", cs.Changes)
	}
}

func TestDiffIgnoresForeignRules(t *testing.T) {
	d := desired()
	o := model.ObservedPolicy{OwnerTag: "illumio-enforcer", Layer: "L", Rules: []model.ObservedRule{
		{UID: "uid-h", IntentID: "", Name: "human-rule", Action: "allow", Position: 1},
	}}
	cs := Diff(d, o)
	if len(cs.Changes) != 0 {
		t.Fatalf("foreign rule must never appear in a changeset, got %+v", cs.Changes)
	}
}

func TestDiffUpdatesChangedRule(t *testing.T) {
	d := desired(intent.DesiredRule{IntentID: "r1", Name: "n1", Services: []string{"tcp/443"}, Action: "allow", Position: 1})
	o := model.ObservedPolicy{OwnerTag: "illumio-enforcer", Layer: "L", Rules: []model.ObservedRule{
		{UID: "uid-1", IntentID: "r1", Name: "n1", Services: []string{"tcp/80"}, Action: "allow", Position: 1},
	}}
	cs := Diff(d, o)
	if len(cs.Changes) != 1 || cs.Changes[0].Op != model.OpUpdate || cs.Changes[0].UID != "uid-1" {
		t.Fatalf("expected one update of uid-1, got %+v", cs.Changes)
	}
}

func TestDiffMoveOnPositionChange(t *testing.T) {
	d := desired(intent.DesiredRule{IntentID: "r1", Name: "n1", Action: "allow", Position: 2})
	o := model.ObservedPolicy{OwnerTag: "illumio-enforcer", Layer: "L", Rules: []model.ObservedRule{
		{UID: "uid-1", IntentID: "r1", Name: "n1", Action: "allow", Position: 1},
	}}
	cs := Diff(d, o)
	if len(cs.Changes) != 1 || cs.Changes[0].Op != model.OpMove {
		t.Fatalf("expected one move, got %+v", cs.Changes)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/plan/ -v`
Expected: FAIL — `undefined: Diff`.

- [ ] **Step 4: Write minimal implementation**

`internal/plan/diff.go`:

```go
package plan

import (
	"reflect"
	"sort"

	"github.com/alexgoller/illumio-policy-enforcer/internal/intent"
	"github.com/alexgoller/illumio-policy-enforcer/internal/model"
)

// Diff computes the changes needed to make the engine's OWNED rules in the
// observed policy match the desired policy. Foreign rules (IntentID == "")
// are never touched. Output is sorted by IntentID for determinism.
func Diff(d intent.DesiredPolicy, o model.ObservedPolicy) model.ChangeSet {
	owned := map[string]model.ObservedRule{}
	for _, r := range o.Rules {
		if r.IntentID != "" {
			owned[r.IntentID] = r
		}
	}
	desiredByID := map[string]intent.DesiredRule{}
	for _, r := range d.Rules {
		desiredByID[r.IntentID] = r
	}

	var changes []model.Change

	for _, dr := range d.Rules {
		dr := dr
		ex, ok := owned[dr.IntentID]
		if !ok {
			changes = append(changes, model.Change{Op: model.OpCreate, IntentID: dr.IntentID, Desired: &dr, Reason: "not present in owned layer"})
			continue
		}
		if !sameFields(dr, ex) {
			changes = append(changes, model.Change{Op: model.OpUpdate, IntentID: dr.IntentID, UID: ex.UID, Desired: &dr, Reason: "field drift"})
		} else if dr.Position != ex.Position {
			changes = append(changes, model.Change{Op: model.OpMove, IntentID: dr.IntentID, UID: ex.UID, Desired: &dr, Reason: "position drift"})
		}
	}

	for id, ex := range owned {
		if _, ok := desiredByID[id]; !ok {
			changes = append(changes, model.Change{Op: model.OpDelete, IntentID: id, UID: ex.UID, Reason: "no longer in desired"})
		}
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].IntentID < changes[j].IntentID })
	return model.ChangeSet{OwnerTag: d.OwnerTag, Layer: d.Layer, Changes: changes}
}

func sameFields(d intent.DesiredRule, o model.ObservedRule) bool {
	return d.Name == o.Name &&
		d.Action == o.Action &&
		reflect.DeepEqual(d.Sources, o.Sources) &&
		reflect.DeepEqual(d.Destinations, o.Destinations) &&
		reflect.DeepEqual(d.Services, o.Services)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/plan/ -v`
Expected: PASS (all five).

- [ ] **Step 6: Commit**

```bash
git add internal/model internal/plan
git commit -m "feat(plan): managed-block diff over owned rules, ignores foreign rules"
```

---

### Task 4: Safety — ownership confinement assertion

**Files:**
- Create: `internal/safety/ownership.go`
- Test: `internal/safety/ownership_test.go`

**Interfaces:**
- Consumes: `model.ChangeSet`, `model.ObservedPolicy`.
- Produces: `func safety.AssertOwned(cs model.ChangeSet, o model.ObservedPolicy) error`. Returns a non-nil error if any change touches a UID that is not an owned rule (`IntentID == ""` or unknown UID). This is the last line of defense before any apply in P2+.

- [ ] **Step 1: Write the failing test**

`internal/safety/ownership_test.go`:

```go
package safety

import (
	"testing"

	"github.com/alexgoller/illumio-policy-enforcer/internal/model"
)

func observed(rules ...model.ObservedRule) model.ObservedPolicy {
	return model.ObservedPolicy{OwnerTag: "illumio-enforcer", Layer: "L", Rules: rules}
}

func TestAssertOwnedAllowsOwnedUID(t *testing.T) {
	o := observed(model.ObservedRule{UID: "uid-1", IntentID: "r1"})
	cs := model.ChangeSet{Changes: []model.Change{{Op: model.OpUpdate, UID: "uid-1", IntentID: "r1"}}}
	if err := AssertOwned(cs, o); err != nil {
		t.Fatalf("owned UID must pass: %v", err)
	}
}

func TestAssertOwnedRejectsForeignUID(t *testing.T) {
	o := observed(model.ObservedRule{UID: "uid-h", IntentID: ""}) // human rule
	cs := model.ChangeSet{Changes: []model.Change{{Op: model.OpDelete, UID: "uid-h"}}}
	if err := AssertOwned(cs, o); err == nil {
		t.Fatal("must reject a change targeting a foreign rule")
	}
}

func TestAssertOwnedRejectsUnknownUID(t *testing.T) {
	o := observed()
	cs := model.ChangeSet{Changes: []model.Change{{Op: model.OpDelete, UID: "ghost"}}}
	if err := AssertOwned(cs, o); err == nil {
		t.Fatal("must reject a change targeting an unknown UID")
	}
}

func TestAssertOwnedAllowsCreate(t *testing.T) {
	cs := model.ChangeSet{Changes: []model.Change{{Op: model.OpCreate, IntentID: "r1"}}}
	if err := AssertOwned(cs, observed()); err != nil {
		t.Fatalf("create has no UID and must pass: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/safety/ -v`
Expected: FAIL — `undefined: AssertOwned`.

- [ ] **Step 3: Write minimal implementation**

`internal/safety/ownership.go`:

```go
package safety

import (
	"fmt"

	"github.com/alexgoller/illumio-policy-enforcer/internal/model"
)

// AssertOwned guarantees a ChangeSet only ever mutates rules the engine owns.
// Any change carrying a UID must match an observed rule whose IntentID != "".
// Creates carry no UID and are always allowed. This is a hard boundary: a
// violation is a programming error, not a recoverable condition.
func AssertOwned(cs model.ChangeSet, o model.ObservedPolicy) error {
	ownedUID := map[string]bool{}
	for _, r := range o.Rules {
		if r.IntentID != "" {
			ownedUID[r.UID] = true
		}
	}
	for _, c := range cs.Changes {
		if c.UID == "" {
			continue // create
		}
		if !ownedUID[c.UID] {
			return fmt.Errorf("safety violation: change %s targets non-owned rule UID %q", c.Op, c.UID)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/safety/ -v`
Expected: PASS (all four).

- [ ] **Step 5: Commit**

```bash
git add internal/safety
git commit -m "feat(safety): managed-scope assertion — reject changes to foreign rules"
```

---

### Task 5: Check Point Management client (login / logout / show-access-rulebase)

**Files:**
- Create: `internal/adapter/checkpoint/client.go`
- Test: `internal/adapter/checkpoint/client_test.go`
- Create: `testdata/cp_show_access_rulebase.json`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `type Client struct { ... }`
  - `func New(baseURL string, httpClient *http.Client) *Client`
  - `func (c *Client) Login(ctx context.Context, user, password string) error` — POSTs `/web_api/login`, stores the returned `sid`.
  - `func (c *Client) Logout(ctx context.Context) error`
  - `func (c *Client) ShowAccessRulebase(ctx context.Context, layer string) (RawRulebase, error)` — POSTs `/web_api/show-access-rulebase` with `X-chkp-sid`, returns the decoded JSON.
  - `type RawRulebase struct { ... }` mirroring the fields Task 6 needs (`rulebase []RawRule`, each with `uid`, `name`, `custom-fields`, `source`, `destination`, `service`, `action`).

- [ ] **Step 1: Record the fixture**

`testdata/cp_show_access_rulebase.json` (a minimal but representative `show-access-rulebase` response; two owned rules tagged in `field-1`, one foreign rule):

```json
{
  "name": "Illumio-Managed",
  "rulebase": [
    {"uid": "uid-1", "name": "web-to-db", "type": "access-rule",
     "custom-fields": {"field-1": "illumio-enforcer:web-db"},
     "source": ["grp-web"], "destination": ["grp-db"], "service": ["tcp/5432"],
     "action": {"name": "Accept"}},
    {"uid": "uid-2", "name": "app-to-cache", "type": "access-rule",
     "custom-fields": {"field-1": "illumio-enforcer:app-cache"},
     "source": ["grp-app"], "destination": ["grp-cache"], "service": ["tcp/6379"],
     "action": {"name": "Accept"}},
    {"uid": "uid-h", "name": "admin-access", "type": "access-rule",
     "custom-fields": {"field-1": ""},
     "source": ["Any"], "destination": ["Any"], "service": ["ssh"],
     "action": {"name": "Accept"}}
  ]
}
```

- [ ] **Step 2: Write the failing test (httptest, no live firewall)**

`internal/adapter/checkpoint/client_test.go`:

```go
package checkpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestLoginAndShowRulebase(t *testing.T) {
	fixture, err := os.ReadFile("../../../testdata/cp_show_access_rulebase.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/web_api/login":
			json.NewEncoder(w).Encode(map[string]string{"sid": "SID123", "uid": "u"})
		case "/web_api/show-access-rulebase":
			if r.Header.Get("X-chkp-sid") != "SID123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Write(fixture)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	if err := c.Login(context.Background(), "admin", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
	rb, err := c.ShowAccessRulebase(context.Background(), "Illumio-Managed")
	if err != nil {
		t.Fatalf("show: %v", err)
	}
	if len(rb.Rulebase) != 3 || rb.Rulebase[0].UID != "uid-1" {
		t.Fatalf("unexpected rulebase: %+v", rb)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/adapter/checkpoint/ -v`
Expected: FAIL — `undefined: New`.

- [ ] **Step 4: Write minimal implementation**

`internal/adapter/checkpoint/client.go`:

```go
package checkpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type Client struct {
	baseURL string
	http    *http.Client
	sid     string
}

func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: baseURL, http: httpClient}
}

type RawAction struct {
	Name string `json:"name"`
}

type RawRule struct {
	UID          string            `json:"uid"`
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	CustomFields map[string]string `json:"custom-fields"`
	Source       []string          `json:"source"`
	Destination  []string          `json:"destination"`
	Service      []string          `json:"service"`
	Action       RawAction         `json:"action"`
}

type RawRulebase struct {
	Name     string    `json:"name"`
	Rulebase []RawRule `json:"rulebase"`
}

func (c *Client) post(ctx context.Context, cmd string, body any, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/web_api/"+cmd, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.sid != "" {
		req.Header.Set("X-chkp-sid", c.sid)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("checkpoint %s: HTTP %d", cmd, resp.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Login(ctx context.Context, user, password string) error {
	var out struct {
		SID string `json:"sid"`
	}
	if err := c.post(ctx, "login", map[string]string{"user": user, "password": password}, &out); err != nil {
		return err
	}
	if out.SID == "" {
		return fmt.Errorf("checkpoint login: empty sid")
	}
	c.sid = out.SID
	return nil
}

func (c *Client) Logout(ctx context.Context) error {
	return c.post(ctx, "logout", map[string]string{}, nil)
}

func (c *Client) ShowAccessRulebase(ctx context.Context, layer string) (RawRulebase, error) {
	var rb RawRulebase
	body := map[string]any{"name": layer, "details-level": "full", "limit": 500}
	if err := c.post(ctx, "show-access-rulebase", body, &rb); err != nil {
		return RawRulebase{}, err
	}
	return rb, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/adapter/checkpoint/ -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/adapter/checkpoint/client.go internal/adapter/checkpoint/client_test.go testdata/cp_show_access_rulebase.json
git commit -m "feat(checkpoint): read-only Management client (login/logout/show-access-rulebase)"
```

---

### Task 6: Check Point ReadState → ObservedPolicy

**Files:**
- Create: `internal/adapter/checkpoint/readstate.go`
- Test: `internal/adapter/checkpoint/readstate_test.go`

**Interfaces:**
- Consumes: `RawRulebase` (Task 5), `model.ObservedPolicy` (Task 3).
- Produces:
  - `func ToObserved(rb RawRulebase, ownerTag string) model.ObservedPolicy` — maps CP rules to `model.ObservedRule`, extracting `IntentID` from `custom-fields.field-1` (format `"<ownerTag>:<intentID>"`); rules whose `field-1` prefix doesn't match `ownerTag` get `IntentID == ""` (foreign). Position is 1-based order in the rulebase. `Accept`→`allow`, else `deny`.
  - `func (c *Client) ReadState(ctx context.Context, layer, ownerTag string) (model.ObservedPolicy, error)` — `ShowAccessRulebase` + `ToObserved`.

- [ ] **Step 1: Write the failing test**

`internal/adapter/checkpoint/readstate_test.go`:

```go
package checkpoint

import "testing"

func TestToObservedExtractsOwnedIntentIDs(t *testing.T) {
	rb := RawRulebase{Name: "Illumio-Managed", Rulebase: []RawRule{
		{UID: "uid-1", Name: "web-to-db", CustomFields: map[string]string{"field-1": "illumio-enforcer:web-db"},
			Source: []string{"grp-web"}, Destination: []string{"grp-db"}, Service: []string{"tcp/5432"}, Action: RawAction{Name: "Accept"}},
		{UID: "uid-h", Name: "admin", CustomFields: map[string]string{"field-1": ""},
			Action: RawAction{Name: "Accept"}},
	}}
	o := ToObserved(rb, "illumio-enforcer")
	if len(o.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(o.Rules))
	}
	if o.Rules[0].IntentID != "web-db" || o.Rules[0].UID != "uid-1" || o.Rules[0].Position != 1 {
		t.Fatalf("owned rule mismapped: %+v", o.Rules[0])
	}
	if o.Rules[0].Action != "allow" {
		t.Fatalf("Accept should map to allow, got %q", o.Rules[0].Action)
	}
	if o.Rules[1].IntentID != "" {
		t.Fatalf("foreign rule must have empty IntentID, got %q", o.Rules[1].IntentID)
	}
}

func TestToObservedIgnoresOtherOwnerTags(t *testing.T) {
	rb := RawRulebase{Rulebase: []RawRule{
		{UID: "x", Name: "n", CustomFields: map[string]string{"field-1": "someone-else:r9"}, Action: RawAction{Name: "Drop"}},
	}}
	o := ToObserved(rb, "illumio-enforcer")
	if o.Rules[0].IntentID != "" {
		t.Fatalf("rule owned by a different tag must be treated as foreign, got %q", o.Rules[0].IntentID)
	}
	if o.Rules[0].Action != "deny" {
		t.Fatalf("Drop should map to deny, got %q", o.Rules[0].Action)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/adapter/checkpoint/ -run TestToObserved -v`
Expected: FAIL — `undefined: ToObserved`.

- [ ] **Step 3: Write minimal implementation**

`internal/adapter/checkpoint/readstate.go`:

```go
package checkpoint

import (
	"context"
	"strings"

	"github.com/alexgoller/illumio-policy-enforcer/internal/model"
)

func ToObserved(rb RawRulebase, ownerTag string) model.ObservedPolicy {
	out := model.ObservedPolicy{OwnerTag: ownerTag, Layer: rb.Name}
	for i, r := range rb.Rulebase {
		intentID := ""
		if f1 := r.CustomFields["field-1"]; f1 != "" {
			if tag, id, ok := strings.Cut(f1, ":"); ok && tag == ownerTag {
				intentID = id
			}
		}
		action := "deny"
		if r.Action.Name == "Accept" {
			action = "allow"
		}
		out.Rules = append(out.Rules, model.ObservedRule{
			UID: r.UID, IntentID: intentID, Name: r.Name,
			Sources: r.Source, Destinations: r.Destination, Services: r.Service,
			Action: action, Position: i + 1,
		})
	}
	return out
}

func (c *Client) ReadState(ctx context.Context, layer, ownerTag string) (model.ObservedPolicy, error) {
	rb, err := c.ShowAccessRulebase(ctx, layer)
	if err != nil {
		return model.ObservedPolicy{}, err
	}
	return ToObserved(rb, ownerTag), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adapter/checkpoint/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/checkpoint/readstate.go internal/adapter/checkpoint/readstate_test.go
git commit -m "feat(checkpoint): ReadState maps owned rules to ObservedPolicy by owner tag"
```

---

### Task 7: GitOps Terraform render for Check Point

**Files:**
- Create: `internal/delivery/gitops/checkpoint.go`
- Test: `internal/delivery/gitops/checkpoint_test.go`
- Create: `testdata/expected_checkpoint.tf`

**Interfaces:**
- Consumes: `intent.DesiredPolicy`.
- Produces: `func RenderCheckpoint(d intent.DesiredPolicy) (string, error)` — renders one `checkpoint_management_access_rule` resource per desired rule, referencing the owned `layer`, positioning by `position` (`above`/`below` chain not needed in P1 — use `position` = `bottom` with explicit ordering via `depends_on` comments), stamping `custom_fields.field_1 = "<owner_tag>:<intent_id>"`. Output is deterministic (rules in `Position` order).

- [ ] **Step 1: Write the failing test**

`internal/delivery/gitops/checkpoint_test.go`:

```go
package gitops

import (
	"os"
	"strings"
	"testing"

	"github.com/alexgoller/illumio-policy-enforcer/internal/intent"
)

func TestRenderCheckpointGolden(t *testing.T) {
	d := intent.DesiredPolicy{
		OwnerTag: "illumio-enforcer", Layer: "Illumio-Managed",
		Rules: []intent.DesiredRule{
			{IntentID: "web-db", Name: "web-to-db", Sources: []string{"grp-web"},
				Destinations: []string{"grp-db"}, Services: []string{"tcp/5432"}, Action: "allow", Position: 1},
		},
	}
	got, err := RenderCheckpoint(d)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../../testdata/expected_checkpoint.tf")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(string(want)) {
		t.Fatalf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
```

- [ ] **Step 2: Write the golden file**

`testdata/expected_checkpoint.tf`:

```hcl
resource "checkpoint_management_access_rule" "web_db" {
  layer    = "Illumio-Managed"
  name     = "web-to-db"
  position = { top = "Illumio-Managed" }
  source      = ["grp-web"]
  destination = ["grp-db"]
  service     = ["tcp/5432"]
  action      = "Accept"
  custom_fields = {
    field_1 = "illumio-enforcer:web-db"
  }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/delivery/gitops/ -v`
Expected: FAIL — `undefined: RenderCheckpoint`.

- [ ] **Step 4: Write minimal implementation**

`internal/delivery/gitops/checkpoint.go`:

```go
package gitops

import (
	"sort"
	"strings"
	"text/template"

	"github.com/alexgoller/illumio-policy-enforcer/internal/intent"
)

var cpTmpl = template.Must(template.New("cp").Funcs(template.FuncMap{
	"tfname": func(s string) string { return strings.NewReplacer("-", "_", " ", "_").Replace(s) },
	"action": func(a string) string {
		if a == intent.ActionAllow {
			return "Accept"
		}
		return "Drop"
	},
	"list": func(items []string) string {
		q := make([]string, len(items))
		for i, s := range items {
			q[i] = "\"" + s + "\""
		}
		return "[" + strings.Join(q, ", ") + "]"
	},
}).Parse(`resource "checkpoint_management_access_rule" "{{ tfname .IntentID }}" {
  layer    = "{{ $.Layer }}"
  name     = "{{ .Name }}"
  position = { top = "{{ $.Layer }}" }
  source      = {{ list .Sources }}
  destination = {{ list .Destinations }}
  service     = {{ list .Services }}
  action      = "{{ action .Action }}"
  custom_fields = {
    field_1 = "{{ $.OwnerTag }}:{{ .IntentID }}"
  }
}`))

func RenderCheckpoint(d intent.DesiredPolicy) (string, error) {
	rules := append([]intent.DesiredRule(nil), d.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].Position < rules[j].Position })

	type ctx struct {
		intent.DesiredRule
		Layer    string
		OwnerTag string
	}
	var b strings.Builder
	for i, r := range rules {
		if i > 0 {
			b.WriteString("\n\n")
		}
		if err := cpTmpl.Execute(&b, ctx{DesiredRule: r, Layer: d.Layer, OwnerTag: d.OwnerTag}); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/delivery/gitops/ -v`
Expected: PASS. (If the golden mismatches on whitespace, align the golden file to the template output — the template is the source of truth.)

- [ ] **Step 6: Commit**

```bash
git add internal/delivery/gitops testdata/expected_checkpoint.tf
git commit -m "feat(gitops): render Check Point access rules as Terraform from DesiredPolicy"
```

---

### Task 8: CLI `plan` command + backend-equivalence test

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/planner/planner.go`
- Test: `internal/planner/planner_test.go`
- Modify: `cmd/enforcer/main.go`
- Create: `testdata/cp_config.yaml`

**Interfaces:**
- Consumes: `intent.Load`, `checkpoint.New/Login/ReadState`, `plan.Diff`, `safety.AssertOwned`, `gitops.RenderCheckpoint`, `config.Load`.
- Produces:
  - `config.Run struct { Vendor, MgmtHost, Layer, OwnerTag string; UserEnv, PasswordEnv string }`, `func config.Load(path string) (Run, error)`.
  - `planner.Result struct { ChangeSet model.ChangeSet; TerraformHCL string }`.
  - `func planner.Plan(ctx, run config.Run, d intent.DesiredPolicy, adp Reader) (planner.Result, error)` where `Reader` is `interface { ReadState(ctx, layer, ownerTag string) (model.ObservedPolicy, error) }` — so tests inject a fake reader (no live firewall).
  - `func planner.BackendsAgree(cs model.ChangeSet, hcl string) error` — asserts every `OpCreate` rule in the ChangeSet appears (by `field_1 = owner:intent_id`) in the rendered HCL, proving the direct-API and GitOps backends describe the same owned rules.

- [ ] **Step 1: Write the failing test (fake reader, no network)**

`internal/planner/planner_test.go`:

```go
package planner

import (
	"context"
	"testing"

	"github.com/alexgoller/illumio-policy-enforcer/internal/config"
	"github.com/alexgoller/illumio-policy-enforcer/internal/intent"
	"github.com/alexgoller/illumio-policy-enforcer/internal/model"
)

type fakeReader struct{ o model.ObservedPolicy }

func (f fakeReader) ReadState(_ context.Context, _, _ string) (model.ObservedPolicy, error) {
	return f.o, nil
}

func TestPlanProducesChangeSetAndTF(t *testing.T) {
	d := intent.DesiredPolicy{OwnerTag: "illumio-enforcer", Layer: "Illumio-Managed",
		Rules: []intent.DesiredRule{{IntentID: "web-db", Name: "web-to-db", Sources: []string{"grp-web"},
			Destinations: []string{"grp-db"}, Services: []string{"tcp/5432"}, Action: "allow", Position: 1}}}
	run := config.Run{Vendor: "checkpoint", Layer: "Illumio-Managed", OwnerTag: "illumio-enforcer"}
	res, err := Plan(context.Background(), run, d, fakeReader{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.ChangeSet.Changes) != 1 || res.ChangeSet.Changes[0].Op != model.OpCreate {
		t.Fatalf("expected one create, got %+v", res.ChangeSet.Changes)
	}
	if err := BackendsAgree(res.ChangeSet, res.TerraformHCL); err != nil {
		t.Fatalf("backends must agree: %v", err)
	}
}

func TestPlanRejectsForeignTargeting(t *testing.T) {
	// desired empty; observed has a foreign rule -> diff yields no changes, so safety passes.
	// This guards the wiring: safety runs and does not spuriously fail on foreign rules.
	run := config.Run{Vendor: "checkpoint", Layer: "L", OwnerTag: "illumio-enforcer"}
	o := model.ObservedPolicy{OwnerTag: "illumio-enforcer", Layer: "L",
		Rules: []model.ObservedRule{{UID: "uid-h", IntentID: "", Name: "human"}}}
	res, err := Plan(context.Background(), run, intent.DesiredPolicy{OwnerTag: "illumio-enforcer", Layer: "L"}, fakeReader{o})
	if err != nil {
		t.Fatalf("safety must pass when no owned change touches the foreign rule: %v", err)
	}
	if len(res.ChangeSet.Changes) != 0 {
		t.Fatalf("expected no changes, got %+v", res.ChangeSet.Changes)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/planner/ -v`
Expected: FAIL — `undefined: Plan`.

- [ ] **Step 3: Write the config loader**

`internal/config/config.go`:

```go
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Run struct {
	Vendor      string `yaml:"vendor"`
	MgmtHost    string `yaml:"mgmt_host"`
	Layer       string `yaml:"layer"`
	OwnerTag    string `yaml:"owner_tag"`
	UserEnv     string `yaml:"user_env"`
	PasswordEnv string `yaml:"password_env"`
}

func Load(path string) (Run, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Run{}, err
	}
	var r Run
	if err := yaml.Unmarshal(b, &r); err != nil {
		return Run{}, err
	}
	if r.Vendor != "checkpoint" {
		return Run{}, fmt.Errorf("P1 supports only vendor=checkpoint, got %q", r.Vendor)
	}
	return r, nil
}
```

(Run `go get gopkg.in/yaml.v3` before this step.)

- [ ] **Step 4: Write the planner**

`internal/planner/planner.go`:

```go
package planner

import (
	"context"
	"fmt"
	"strings"

	"github.com/alexgoller/illumio-policy-enforcer/internal/config"
	"github.com/alexgoller/illumio-policy-enforcer/internal/delivery/gitops"
	"github.com/alexgoller/illumio-policy-enforcer/internal/intent"
	"github.com/alexgoller/illumio-policy-enforcer/internal/model"
	"github.com/alexgoller/illumio-policy-enforcer/internal/plan"
	"github.com/alexgoller/illumio-policy-enforcer/internal/safety"
)

type Reader interface {
	ReadState(ctx context.Context, layer, ownerTag string) (model.ObservedPolicy, error)
}

type Result struct {
	ChangeSet    model.ChangeSet
	TerraformHCL string
}

func Plan(ctx context.Context, run config.Run, d intent.DesiredPolicy, adp Reader) (Result, error) {
	observed, err := adp.ReadState(ctx, run.Layer, run.OwnerTag)
	if err != nil {
		return Result{}, fmt.Errorf("read state: %w", err)
	}
	cs := plan.Diff(d, observed)
	if err := safety.AssertOwned(cs, observed); err != nil {
		return Result{}, err
	}
	hcl, err := gitops.RenderCheckpoint(d)
	if err != nil {
		return Result{}, err
	}
	return Result{ChangeSet: cs, TerraformHCL: hcl}, nil
}

func BackendsAgree(cs model.ChangeSet, hcl string) error {
	for _, c := range cs.Changes {
		if c.Op != model.OpCreate {
			continue
		}
		marker := fmt.Sprintf("%s:%s", cs.OwnerTag, c.IntentID)
		if !strings.Contains(hcl, marker) {
			return fmt.Errorf("create %q present in ChangeSet but missing from Terraform (marker %q)", c.IntentID, marker)
		}
	}
	return nil
}
```

- [ ] **Step 5: Wire the CLI**

Replace the `plan` case in `cmd/enforcer/main.go` with real wiring:

```go
	case "plan":
		fs := flag.NewFlagSet("plan", flag.ExitOnError)
		intentPath := fs.String("intent", "", "path to DesiredPolicy JSON")
		configPath := fs.String("config", "", "path to run config YAML")
		renderTF := fs.String("render-tf", "", "optional path to write rendered Terraform")
		_ = fs.Parse(os.Args[2:])

		run, err := config.Load(*configPath)
		must(err)
		f, err := os.Open(*intentPath)
		must(err)
		defer f.Close()
		d, err := intent.Load(f)
		must(err)

		user := os.Getenv(run.UserEnv)
		pw := os.Getenv(run.PasswordEnv)
		client := checkpoint.New("https://"+run.MgmtHost, insecureClient())
		must(client.Login(context.Background(), user, pw))
		defer client.Logout(context.Background())

		res, err := planner.Plan(context.Background(), run, d, client)
		must(err)
		must(planner.BackendsAgree(res.ChangeSet, res.TerraformHCL))

		printChangeSet(res.ChangeSet)
		if *renderTF != "" {
			must(os.WriteFile(*renderTF, []byte(res.TerraformHCL), 0o644))
			fmt.Fprintf(os.Stderr, "wrote Terraform to %s\n", *renderTF)
		}
```

Add the supporting helpers (`must`, `insecureClient`, `printChangeSet`) and imports (`flag`, `context`, the internal packages, `crypto/tls`, `net/http`) in `cmd/enforcer/main.go`:

```go
func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func insecureClient() *http.Client {
	// Lab pilot only. Production must pin the CA. Mirrors PCE_TLS_SKIP_VERIFY posture.
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func printChangeSet(cs model.ChangeSet) {
	fmt.Printf("Plan for layer %q (owner %q): %d change(s)\n", cs.Layer, cs.OwnerTag, len(cs.Changes))
	for _, c := range cs.Changes {
		fmt.Printf("  %-6s %-16s %s\n", c.Op, c.IntentID, c.Reason)
	}
	if len(cs.Changes) == 0 {
		fmt.Println("  (in sync — no changes)")
	}
}
```

- [ ] **Step 6: Create the sample run config**

`testdata/cp_config.yaml`:

```yaml
vendor: checkpoint
mgmt_host: cp-mgmt.lab.example.com
layer: Illumio-Managed
owner_tag: illumio-enforcer
user_env: CP_MGMT_USER
password_env: CP_MGMT_PASSWORD
```

- [ ] **Step 7: Run tests + build**

Run: `go test ./... -v && go build ./...`
Expected: all PASS, binary builds.

- [ ] **Step 8: Commit**

```bash
git add internal/config internal/planner cmd/enforcer/main.go testdata/cp_config.yaml go.mod go.sum
git commit -m "feat(cli): enforcer plan — dry-run diff + Terraform render + backend-equivalence"
```

---

### Task 9: Live-lab validation (LAB-GATED — requires a Check Point Management server)

> This task has **no unit test**; it is the pilot's exit gate against real hardware. It requires a lab CP Management server, a test gateway, a dedicated owned layer `Illumio-Managed`, and a permission-scoped API admin that can read only that layer. **Read-only in P1** — do not enable any write path.

**Files:**
- Create: `docs/pilot/checkpoint-validation.md` (record results here)

- [ ] **Step 1: Prepare the lab**
  - Enable the CP Management API (`SmartConsole → Manage & Settings → Blades → Management API → All IP addresses`), `api restart`.
  - Create an ordered layer `Illumio-Managed`; add 2–3 rules by hand with `custom-fields.field-1 = "illumio-enforcer:<id>"`; add one *foreign* rule with empty `field-1`.
  - Create an API admin whose permission profile can **read** only that layer; put its creds in `CP_MGMT_USER`/`CP_MGMT_PASSWORD`.

- [ ] **Step 2: Export a matching DesiredPolicy**
  - From `policy-resolver` (or hand-write) a `desired.json` whose `intent_id`s match the hand-created owned rules, with one intentional difference (a changed service and one extra rule) so the plan is non-empty.

- [ ] **Step 3: Run the plan against the lab**

Run:
```bash
CP_MGMT_USER=... CP_MGMT_PASSWORD=... \
  ./enforcer plan --intent desired.json --config testdata/cp_config.yaml --render-tf out.tf
```

- [ ] **Step 4: Verify the five success criteria (record each in `docs/pilot/checkpoint-validation.md`)**
  1. **Provable confinement:** the ChangeSet contains **no** change with the foreign rule's UID; `AssertOwned` passed. Confirm the foreign rule never appears.
  2. **Plan fidelity:** the printed changes exactly match the intentional differences you introduced (the changed service → `update`, the extra rule → `create`); nothing spurious.
  3. **Backend equivalence:** `BackendsAgree` passed and `out.tf` contains a `checkpoint_management_access_rule` for each `create`, tagged `field_1 = "illumio-enforcer:<id>"`.
  4. **Read isolation:** the scoped API admin could read only `Illumio-Managed` (attempting another layer errors) — confirms least privilege.
  5. **Rate posture:** a single login + single `show-access-rulebase` per run (no login-per-call); note the R81 login-frequency limit for P2 design.

- [ ] **Step 5: Write up findings + commit**
  - Record pass/fail per criterion, any API surprises (ordering, `details-level`, pagination past 500 rules), and the **verify** items resolved (rollback API surface, login-rate numbers) for the P2 plan.

```bash
git add docs/pilot/checkpoint-validation.md
git commit -m "docs(pilot): Check Point dry-run validation results"
```

---

## Self-Review

**1. Spec coverage (against the design doc):**
- Intent layer / `DesiredPolicy` contract → Task 2. ✓
- Managed-block rule model → Task 3 diff. ✓ (`ip-literal` is explicitly out of P1 scope per Global Constraints.)
- Delivery backends: `gitops` render → Task 7; `direct-api` read → Tasks 5–6; equivalence → Task 8. ✓ (Apply/commit is P2, per "dry-run only".)
- Vendor adapter interface (`ReadState`, `Plan`) → Tasks 5,6,8. ✓ (`Apply/Rollback/UpdateMembership` are P2+, not in P1.)
- Safety core: ownership confinement + managed-scope assertion → Task 4; used in Task 8. ✓ (Approval gate, drift dashboards, rate-limiter, reconciler = P2+.)
- Check Point pilot success criteria (§9 of spec) → Task 9 maps 1:1 to the five criteria. ✓
- Reconciler / two-speed loop → **intentionally deferred to P2** (needs the write + membership paths). Noted, not a gap.

**2. Placeholder scan:** No TBD/TODO/"handle errors appropriately" — every code step is complete and runnable. The only "optional/later" references are explicit phase boundaries (P2+), not missing detail.

**3. Type consistency:** `DesiredPolicy`/`DesiredRule` (Task 2) reused verbatim in Tasks 3,7,8. `model.ObservedPolicy`/`ObservedRule`/`Change`/`ChangeSet`/`ChangeOp` (Task 3) reused in Tasks 4,6,8. `checkpoint.Client`/`RawRulebase`/`RawRule`/`ToObserved`/`ReadState` (Tasks 5,6) consumed in Task 8. `planner.Reader` interface matches `checkpoint.Client.ReadState`'s signature `(ctx, layer, ownerTag) (model.ObservedPolicy, error)`. `RenderCheckpoint(intent.DesiredPolicy)` (Task 7) called in Task 8. Consistent.
