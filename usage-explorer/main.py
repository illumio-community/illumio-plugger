#!/usr/bin/env python3
"""
usage-explorer — where and how every policy object is used.

Builds a reverse index over the PCE. For each label, label group, service and
IP list it records:
  - the workloads that carry it (labels), with an exact count and a sample
  - every ruleset rule and deny rule that references it, with the rule number
    (its position in the ruleset) and the role: scope, consumer, provider or
    service, in draft and/or active policy
  - the enforcement boundaries, pairing profiles and label groups that
    reference it
  - the PCE's own label usage flags for everything else (virtual services,
    container workload profiles, RBAC permissions, ...)
Objects nothing references are flagged unused.

Read-only. One index rebuild per POLL_INTERVAL (default hourly).
"""

import re
import time

from plugger_sdk import Plugin

app = Plugin("usage-explorer")

if app.env("PCE_TLS_SKIP_VERIFY", "true").lower() == "true":
    # The operator chose to skip verification; one warning per request just buries the log.
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INCLUDE_DRAFT = app.env("INCLUDE_DRAFT", "true").lower() == "true"
WORKLOAD_SAMPLE = max(0, int(app.env("WORKLOAD_SAMPLE", "50")))
PVERSIONS = ["active"] + (["draft"] if INCLUDE_DRAFT else [])
MAX_RESULTS = 10000

# Label usage flags the PCE reports that this plugin also resolves in detail.
# Every other truthy flag is surfaced as an "other reference" chip.
DETAILED_FLAGS = {"workload", "ruleset", "label_group", "pairing_profile", "enforcement_boundary"}

_last_unused = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def norm(href):
    """Strip the policy version so the draft and active copies of an object share one id."""
    return (href or "").replace("/sec_policy/draft/", "/sec_policy/").replace("/sec_policy/active/", "/sec_policy/")


def console_url(href):
    """PCE console link for an API href (rulesets, IP lists and label groups use different console paths)."""
    m = re.match(r".*/orgs/\d+/(.*)", href or "")
    path = m.group(1) if m else (href or "").lstrip("/")
    for a, b in (("sec_policy/draft/", ""), ("sec_policy/active/", ""), ("sec_policy/", ""),
                 ("rule_sets/", "rulesets/"), ("ip_lists/", "iplists/"), ("label_groups/", "labelgroups/")):
        path = path.replace(a, b)
    return f"https://{app.env('PCE_HOST', 'localhost')}/#/{path}"


def fetch(pce, path, **params):
    params.setdefault("max_results", MAX_RESULTS)
    try:
        resp = pce.get(path, params=params)
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, list) else []
        app.log.warning("GET %s -> HTTP %s", path, resp.status_code)
    except Exception as e:
        app.log.warning("GET %s failed: %s", path, e)
    return []


def actor_ref(actor):
    """(kind, href) for a rule/scope/boundary actor that names a label, label group or IP list."""
    if not isinstance(actor, dict):
        return None, None
    for kind in ("label", "label_group", "ip_list"):
        ref = actor.get(kind)
        if isinstance(ref, dict) and ref.get("href"):
            return kind, ref["href"]
    return None, None


# ---------------------------------------------------------------------------
# Index build
# ---------------------------------------------------------------------------

class Index:
    def __init__(self):
        self.objects = {}

    def obj(self, kind, href, name=None, **extra):
        """Get-or-create the record for an object. A reference to an href that is not in
        the catalog (deleted, or outside the fetched policy versions) gets a stub marked missing."""
        oid = norm(href)
        rec = self.objects.get(oid)
        if rec is None:
            rec = {
                "id": oid, "kind": kind, "href": href, "name": name or oid.rsplit("/", 1)[-1],
                "missing": name is None, "pversions": [], "flags": [], "members": None,
                "workloads": {"count": 0, "sample": []},
                "rules": {}, "boundaries": {}, "label_groups": {}, "pairing_profiles": {},
            }
            self.objects[oid] = rec
        elif name:
            rec["name"] = name
            rec["missing"] = False
        rec.update(extra)
        return rec

    @staticmethod
    def add_pv(entry, pv):
        if pv not in entry["pversions"]:
            entry["pversions"].append(pv)

    def add_rule_ref(self, rec, rs, rule, number, role, rtype, pv, enabled, extra_scope=False, exclusion=False):
        rid = norm(rule["href"]) if rule else norm(rs.get("href"))
        key = f"{rid}|{role}"
        e = rec["rules"].get(key)
        if e is None:
            e = {
                "ruleset": rs.get("name") or "", "ruleset_href": rs.get("href"),
                "ruleset_url": console_url(rs.get("href")),
                "rule_href": rule.get("href") if rule else None,
                "role": role, "type": rtype, "number": {}, "enabled": {},
                "extra_scope": extra_scope, "exclusion": exclusion, "pversions": [],
            }
            rec["rules"][key] = e
        e["number"][pv] = number
        e["enabled"][pv] = bool(enabled)
        self.add_pv(e, pv)

    def add_boundary_ref(self, rec, eb, role, pv):
        key = f"{norm(eb.get('href'))}|{role}"
        e = rec["boundaries"].setdefault(key, {
            "name": eb.get("name") or "", "href": eb.get("href"), "url": console_url(eb.get("href")),
            "role": role, "enabled": {}, "pversions": [],
        })
        e["enabled"][pv] = bool(eb.get("enabled", True))
        self.add_pv(e, pv)

    def add_group_ref(self, rec, lg, pv):
        e = rec["label_groups"].setdefault(norm(lg.get("href")), {
            "name": lg.get("name") or "", "href": lg.get("href"), "url": console_url(lg.get("href")),
            "pversions": [],
        })
        self.add_pv(e, pv)


def build_index(pce):
    t0 = time.time()
    ix = Index()

    # -- Catalog: labels (with the PCE's own usage flags) ----------------------
    labels = fetch(pce, "/labels", usage="true")
    for lbl in labels:
        if not lbl.get("href"):
            continue
        rec = ix.obj("label", lbl["href"], f"{lbl.get('key', '')}: {lbl.get('value', '')}",
                     key=lbl.get("key"), value=lbl.get("value"))
        usage = lbl.get("usage") or {}
        rec["flags"] = sorted(k for k, v in usage.items() if v)
    app.log.info("Labels: %d", len(labels))

    # -- Catalog: versioned policy objects --------------------------------------
    rulesets, boundaries, groups = {}, {}, []
    for pv in PVERSIONS:
        for ipl in fetch(pce, f"/sec_policy/{pv}/ip_lists"):
            if ipl.get("href"):
                ix.add_pv(ix.obj("ip_list", ipl["href"], ipl.get("name")), pv)
        for svc in fetch(pce, f"/sec_policy/{pv}/services"):
            if svc.get("href"):
                ix.add_pv(ix.obj("service", svc["href"], svc.get("name")), pv)
        for lg in fetch(pce, f"/sec_policy/{pv}/label_groups"):
            if not lg.get("href"):
                continue
            rec = ix.obj("label_group", lg["href"], lg.get("name"), key=lg.get("key"))
            ix.add_pv(rec, pv)
            rec["members"] = {"labels": len(lg.get("labels") or []), "sub_groups": len(lg.get("sub_groups") or [])}
            groups.append((pv, lg))
        rulesets[pv] = fetch(pce, f"/sec_policy/{pv}/rule_sets")
        boundaries[pv] = fetch(pce, f"/sec_policy/{pv}/enforcement_boundaries")
        app.log.info("%s policy: %d rulesets, %d enforcement boundaries", pv, len(rulesets[pv]), len(boundaries[pv]))

    # -- Workloads -> labels ----------------------------------------------------
    workloads = fetch(pce, "/workloads")
    for wl in workloads:
        for lbl in wl.get("labels") or []:
            href = lbl.get("href") if isinstance(lbl, dict) else None
            if not href:
                continue
            w = ix.obj("label", href)["workloads"]
            w["count"] += 1
            if len(w["sample"]) < WORKLOAD_SAMPLE:
                w["sample"].append({
                    "name": wl.get("name") or wl.get("hostname") or "", "hostname": wl.get("hostname") or "",
                    "href": wl.get("href"), "url": console_url(wl.get("href")),
                    "enforcement_mode": wl.get("enforcement_mode"), "online": wl.get("online"),
                    "managed": wl.get("managed"),
                })
    app.log.info("Workloads: %d", len(workloads))

    # -- Label group membership -------------------------------------------------
    for pv, lg in groups:
        for member in lg.get("labels") or []:
            if member.get("href"):
                ix.add_group_ref(ix.obj("label", member["href"]), lg, pv)
        for sub in lg.get("sub_groups") or []:
            if sub.get("href"):
                ix.add_group_ref(ix.obj("label_group", sub["href"]), lg, pv)

    # -- Pairing profiles -> labels ---------------------------------------------
    for pp in fetch(pce, "/pairing_profiles"):
        for lbl in pp.get("labels") or []:
            if lbl.get("href") and pp.get("href"):
                ix.obj("label", lbl["href"])["pairing_profiles"][pp["href"]] = {
                    "name": pp.get("name") or "", "href": pp["href"], "url": console_url(pp["href"]),
                    "enabled": pp.get("enabled"),
                }

    # -- Rulesets: scopes, rules, deny rules ------------------------------------
    rule_ids, ruleset_ids = set(), set()
    for pv in PVERSIONS:
        for rs in rulesets[pv]:
            ruleset_ids.add(norm(rs.get("href")))
            for scope in rs.get("scopes") or []:
                for item in scope or []:
                    kind, href = actor_ref(item)
                    if kind:
                        ix.add_rule_ref(ix.obj(kind, href), rs, None, None, "scope", "scope", pv,
                                        rs.get("enabled", True), exclusion=bool(item.get("exclusion")))
            for list_name, rtype in (("rules", "allow"), ("deny_rules", "deny")):
                for n, rule in enumerate(rs.get(list_name) or [], start=1):
                    if not rule.get("href"):
                        continue
                    rule_ids.add(norm(rule["href"]))
                    enabled = rule.get("enabled", True)
                    extra = bool(rule.get("unscoped_consumers"))
                    for role in ("consumers", "providers"):
                        for actor in rule.get(role) or []:
                            kind, href = actor_ref(actor)
                            if kind:
                                ix.add_rule_ref(ix.obj(kind, href), rs, rule, n, role[:-1], rtype, pv, enabled, extra)
                    for svc in (rule.get("ingress_services") or []) + (rule.get("egress_services") or []):
                        href = svc.get("href") if isinstance(svc, dict) else None
                        if href:
                            ix.add_rule_ref(ix.obj("service", href), rs, rule, n, "service", rtype, pv, enabled, extra)

    # -- Enforcement boundaries -------------------------------------------------
    boundary_ids = set()
    for pv in PVERSIONS:
        for eb in boundaries[pv]:
            boundary_ids.add(norm(eb.get("href")))
            for role in ("consumers", "providers"):
                for actor in eb.get(role) or []:
                    kind, href = actor_ref(actor)
                    if kind:
                        ix.add_boundary_ref(ix.obj(kind, href), eb, role[:-1], pv)
            for svc in eb.get("ingress_services") or []:
                href = svc.get("href") if isinstance(svc, dict) else None
                if href:
                    ix.add_boundary_ref(ix.obj("service", href), eb, "service", pv)

    # -- Finalize ---------------------------------------------------------------
    def first_number(r):
        return r["number"].get("active") or r["number"].get("draft") or 0

    objects = []
    for rec in ix.objects.values():
        rec["rules"] = sorted(rec["rules"].values(), key=lambda r: (r["ruleset"].lower(), first_number(r), r["role"]))
        rec["boundaries"] = sorted(rec["boundaries"].values(), key=lambda b: b["name"].lower())
        rec["label_groups"] = sorted(rec["label_groups"].values(), key=lambda g: g["name"].lower())
        rec["pairing_profiles"] = sorted(rec["pairing_profiles"].values(), key=lambda p: p["name"].lower())
        rec["other_flags"] = [f for f in rec["flags"] if f not in DETAILED_FLAGS]
        rec["url"] = console_url(rec["href"])
        counts = {
            "workloads": rec["workloads"]["count"], "rules": len(rec["rules"]),
            "boundaries": len(rec["boundaries"]), "label_groups": len(rec["label_groups"]),
            "pairing_profiles": len(rec["pairing_profiles"]), "other": len(rec["other_flags"]),
        }
        rec["counts"] = counts
        rec["total_refs"] = sum(counts.values())
        # The PCE's own flags win: if it says a label is used somewhere we did not
        # resolve (e.g. a draft-only ruleset while INCLUDE_DRAFT is off), it is not unused.
        rec["unused"] = rec["total_refs"] == 0 and not rec["flags"] and not rec["missing"]
        pv = rec["pversions"]
        rec["state"] = ("draft-only" if pv == ["draft"] else "active-only" if pv == ["active"] else "")
        objects.append(rec)

    by_kind = {k: sum(1 for o in objects if o["kind"] == k) for k in ("label", "label_group", "service", "ip_list")}
    unused_by_kind = {k: sum(1 for o in objects if o["kind"] == k and o["unused"]) for k in by_kind}
    counts = {
        "objects": len(objects), "by_kind": by_kind, "unused": sum(unused_by_kind.values()),
        "unused_by_kind": unused_by_kind, "missing": sum(1 for o in objects if o["missing"]),
        "rulesets": len(ruleset_ids), "rules": len(rule_ids), "boundaries": len(boundary_ids),
        "workloads": len(workloads),
    }
    top = sorted((o for o in objects if not o["missing"]),
                 key=lambda o: (-(o["counts"]["workloads"] + o["counts"]["rules"] + o["counts"]["boundaries"]), o["name"]))[:15]
    duration = round(time.time() - t0, 1)
    app.log.info("Index built in %.1fs: %d objects, %d unused, %d rules", duration, len(objects), counts["unused"], counts["rules"])
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "duration_seconds": duration,
        "pversions": PVERSIONS, "workload_sample": WORKLOAD_SAMPLE, "counts": counts,
        "top": [{"id": o["id"], "kind": o["kind"], "name": o["name"], "counts": o["counts"]} for o in top],
        "objects": objects, "error": None,
    }


def publish_report(state):
    """Report when the number of unused objects changes (and once on startup)."""
    global _last_unused
    c = state["counts"]
    if _last_unused is not None and c["unused"] == _last_unused:
        return
    _last_unused = c["unused"]
    unused = sorted((o for o in state["objects"] if o["unused"]), key=lambda o: (o["kind"], o["name"]))
    lines = [f"## Policy object usage", "",
             f"- {c['objects']} objects indexed: {c['by_kind']['label']} labels, {c['by_kind']['label_group']} label groups, "
             f"{c['by_kind']['service']} services, {c['by_kind']['ip_list']} IP lists",
             f"- {c['rules']} rules in {c['rulesets']} rulesets, {c['boundaries']} enforcement boundaries, {c['workloads']} workloads",
             f"- **{c['unused']} unused** (" + ", ".join(f"{v} {k.replace('_', ' ')}s" for k, v in c["unused_by_kind"].items() if v) + ")"]
    if unused:
        lines += ["", "Unused (first 20):"] + [f"- {o['kind'].replace('_', ' ')}: {o['name']}" for o in unused[:20]]
    app.report(title=f"{c['unused']} unused policy objects of {c['objects']}", body="\n".join(lines),
               severity="info", tags=["usage", "hygiene"], data=c)


@app.poll(interval_env="POLL_INTERVAL", default=3600)
def rebuild(pce):
    try:
        state = build_index(pce)
    except Exception as e:
        app.log.exception("Index build failed")
        app.update_state({"error": str(e)})
        return
    app.state = state
    publish_report(state)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def _summary():
    s = app.state
    return {k: v for k, v in s.items() if k != "objects"}


@app.api("GET", "/api/usage")
def api_usage(request):
    return app.state


@app.api("GET", "/api/summary")
def api_summary(request):
    return _summary()


@app.api("GET", "/api/object")
def api_object(request):
    oid = request.query.get("id", "")
    for o in app.state.get("objects", []):
        if o["id"] == oid:
            return o
    return {"error": "not found"}, 404


@app.api("GET", "/api/unused")
def api_unused(request):
    return [o for o in app.state.get("objects", []) if o["unused"]]


@app.api("POST", "/api/rebuild")
def api_rebuild(request):
    app.trigger_poll()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

DASHBOARD = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Usage Explorer</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{dark:{900:'#11111b',800:'#1e1e2e',700:'#313244'}}}}}</script>
<link rel="stylesheet" href="/brand/style.css" onerror="this.remove()">
<style>
.tab-btn{padding:.5rem 1rem;font-size:.875rem;color:#9ca3af;border-bottom:2px solid transparent;white-space:nowrap}
.tab-btn.active{color:#89b4fa;border-color:#89b4fa}
.tab-btn:hover{color:#cdd6f4}
th.sortable{cursor:pointer;user-select:none}
th.sortable:hover{color:#cdd6f4}
tr.row{cursor:pointer}
tr.row:hover{background:rgba(49,50,68,.5)}
tr.row.sel{background:rgba(137,180,250,.12)}
.chip{display:inline-block;font-size:.7rem;line-height:1.1rem;padding:0 .5rem;border-radius:9999px;border:1px solid;white-space:nowrap}
.c-ok{background:rgba(166,227,161,.12);color:#a6e3a1;border-color:rgba(166,227,161,.3)}
.c-bad{background:rgba(243,139,168,.12);color:#f38ba8;border-color:rgba(243,139,168,.3)}
.c-warn{background:rgba(249,226,175,.12);color:#f9e2af;border-color:rgba(249,226,175,.3)}
.c-info{background:rgba(137,180,250,.12);color:#89b4fa;border-color:rgba(137,180,250,.3)}
.c-dim{background:rgba(147,153,178,.12);color:#9399b2;border-color:rgba(147,153,178,.3)}
.c-draft{background:rgba(203,166,247,.12);color:#cba6f7;border-color:rgba(203,166,247,.3)}
.c-active{background:rgba(148,226,213,.12);color:#94e2d5;border-color:rgba(148,226,213,.3)}
.sec{border-top:1px solid #313244;padding-top:.75rem;margin-top:.75rem}
html:not(.dark) .sec{border-color:#e5e7eb}
</style>
</head>
<body class="bg-dark-900 text-gray-300 min-h-screen">
<div class="max-w-7xl mx-auto p-6">

<div class="flex flex-wrap items-center justify-between gap-3 mb-6">
  <div>
    <h1 class="text-2xl font-bold text-white">Usage Explorer</h1>
    <p class="text-sm text-gray-400">Where and how every label, label group, service and IP list is used</p>
  </div>
  <div class="flex items-center gap-3">
    <span id="built" class="text-xs text-gray-500"></span>
    <button onclick="rebuild()" id="rebuild-btn" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-1.5 rounded text-sm font-medium">Rebuild</button>
    <a href="api/usage" target="_blank" class="bg-dark-700 hover:bg-dark-800 text-gray-300 px-4 py-1.5 rounded text-sm border border-gray-600">Export JSON</a>
  </div>
</div>

<div id="error" class="hidden mb-4 text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded px-4 py-2"></div>

<div class="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4"><div id="st-objects" class="text-3xl font-bold text-blue-400">—</div><div class="text-sm text-gray-400 mt-1">Objects</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4"><div id="st-unused" class="text-3xl font-bold text-red-400">—</div><div class="text-sm text-gray-400 mt-1">Unused</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4"><div id="st-rules" class="text-3xl font-bold text-purple-400">—</div><div class="text-sm text-gray-400 mt-1">Rules indexed</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4"><div id="st-rulesets" class="text-3xl font-bold text-green-400">—</div><div class="text-sm text-gray-400 mt-1">Rulesets</div></div>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4"><div id="st-workloads" class="text-3xl font-bold text-yellow-400">—</div><div class="text-sm text-gray-400 mt-1">Workloads</div></div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-5 gap-6">
  <div class="lg:col-span-3">
    <div class="flex gap-1 border-b border-gray-700 mb-4 overflow-x-auto" id="tabs"></div>
    <div class="bg-dark-800 rounded-xl border border-gray-700">
      <div class="p-3 border-b border-gray-700 flex flex-wrap items-center gap-3">
        <input id="search" type="text" placeholder="Search objects, rulesets, workloads..." oninput="renderTable()"
               class="bg-dark-900 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-300 w-72">
        <label class="text-xs text-gray-400 flex items-center gap-1.5 cursor-pointer"><input type="checkbox" id="unused-only" onchange="renderTable()"> Unused only</label>
        <span id="count" class="text-xs text-gray-500 ml-auto"></span>
      </div>
      <div class="overflow-x-auto max-h-[640px] overflow-y-auto">
        <table class="w-full text-sm">
          <thead class="sticky top-0 bg-dark-800 z-10"><tr id="thead" class="text-left text-xs text-gray-400 uppercase"></tr></thead>
          <tbody id="tbody"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div class="lg:col-span-2">
    <div id="detail" class="bg-dark-800 rounded-xl border border-gray-700 p-5 lg:sticky lg:top-6 max-h-[calc(100vh-3rem)] overflow-y-auto text-sm">
      <div class="text-gray-500">Select an object to see where and how it is used.</div>
    </div>
  </div>
</div>

<footer class="mt-8 text-xs text-gray-500 flex flex-wrap gap-x-4 gap-y-1">
  <span>Up <span data-plugger-uptime></span></span>
  <span>Rule numbers are positions within their ruleset (as listed in the PCE console); a rule can sit at a different position in draft and active.</span>
</footer>
</div>

<script>
var DATA = null, tab = 'label', sortKey = 'total_refs', sortDir = -1, sel = null;
var KINDS = {label: 'Labels', label_group: 'Label Groups', service: 'Services', ip_list: 'IP Lists', top: 'Top Impact'};
var FLAG_NAMES = {
  virtual_service: 'Virtual service', virtual_server: 'Virtual server', container_workload: 'Container workload',
  container_workload_profile: 'Container workload profile', permission: 'RBAC permission scope',
  static_policy_scopes: 'Static policy scope', label_mapping_rule: 'Label mapping rule',
  firewall_coexistence_scope: 'Firewall coexistence scope', blocked_connection_reject_scopes: 'Reject connections scope',
  ip_forwarding_enabled_scopes: 'IP forwarding scope', loopback_interfaces_in_policy_scopes: 'Loopback interfaces scope',
  containers_inherit_host_policy_scopes: 'Containers inherit host policy scope', rule_hit_count_enabled_scopes: 'Rule hit count scope'
};
var COLS = [
  {k: 'name', t: 'Object'}, {k: 'rules', t: 'Rules', n: 1}, {k: 'boundaries', t: 'Boundaries', n: 1},
  {k: 'label_groups', t: 'Groups', n: 1}, {k: 'other', t: 'Other', n: 1}, {k: 'workloads', t: 'Workloads', n: 1},
  {k: 'status', t: 'Status'}
];

function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]; }); }
function chip(cls, text) { return '<span class="chip ' + cls + '">' + esc(text) + '</span>'; }
function kindName(k) { return (KINDS[k] || k).replace(/s$/, ''); }
function flagName(f) { return FLAG_NAMES[f] || f.replace(/_/g, ' '); }
function pvChips(pvs) { return (pvs || []).map(function (p) { return chip(p === 'draft' ? 'c-draft' : 'c-active', p); }).join(' '); }
function link(url, text) { return '<a href="' + esc(url) + '" target="_blank" class="text-blue-400 hover:underline">' + esc(text) + '</a>'; }
function status(o) {
  if (o.missing) return chip('c-dim', 'missing');
  if (o.unused) return chip('c-bad', 'unused');
  if (o.state === 'draft-only') return chip('c-warn', 'draft only');
  if (o.state === 'active-only') return chip('c-warn', 'pending delete');
  return chip('c-ok', 'in use');
}
function haystack(o) {
  var parts = [o.name, o.kind];
  o.rules.forEach(function (r) { parts.push(r.ruleset); });
  o.boundaries.forEach(function (b) { parts.push(b.name); });
  o.label_groups.forEach(function (g) { parts.push(g.name); });
  o.pairing_profiles.forEach(function (p) { parts.push(p.name); });
  o.workloads.sample.forEach(function (w) { parts.push(w.name, w.hostname); });
  if (o.unused) parts.push('unused');
  return parts.join(' ').toLowerCase();
}

async function load() {
  try {
    var r = await fetch('api/usage');
    DATA = await r.json();
  } catch (e) { showError('Failed to load index: ' + e); return; }
  if (!DATA.objects) { showError(DATA.error || 'Index not built yet — the first build runs at startup, give it a moment.'); setTimeout(load, 5000); return; }
  if (DATA.error) showError('Last rebuild failed: ' + DATA.error + ' (showing previous index)'); else hideError();
  DATA.objects.forEach(function (o) { o._hay = haystack(o); });
  render();
}
function showError(m) { var e = document.getElementById('error'); e.textContent = m; e.classList.remove('hidden'); }
function hideError() { document.getElementById('error').classList.add('hidden'); }

function render() {
  var c = DATA.counts;
  document.getElementById('st-objects').textContent = c.objects;
  document.getElementById('st-unused').textContent = c.unused;
  document.getElementById('st-rules').textContent = c.rules;
  document.getElementById('st-rulesets').textContent = c.rulesets;
  document.getElementById('st-workloads').textContent = c.workloads;
  document.getElementById('built').textContent = 'Built ' + DATA.generated_at + ' in ' + DATA.duration_seconds + 's · ' + DATA.pversions.join(' + ') + ' policy';
  renderTabs();
  renderTable();
  if (sel) renderDetail(sel);
}

function renderTabs() {
  var html = '';
  Object.keys(KINDS).forEach(function (k) {
    var n = k === 'top' ? '' : ' (' + (DATA.counts.by_kind[k] || 0) + (DATA.counts.unused_by_kind[k] ? ' · ' + DATA.counts.unused_by_kind[k] + ' unused' : '') + ')';
    html += '<button class="tab-btn' + (tab === k ? ' active' : '') + '" onclick="setTab(\'' + k + '\')">' + esc(KINDS[k]) + esc(n) + '</button>';
  });
  document.getElementById('tabs').innerHTML = html;
}
function setTab(k) { tab = k; renderTabs(); renderTable(); }
function setSort(k) { if (sortKey === k) sortDir = -sortDir; else { sortKey = k; sortDir = k === 'name' ? 1 : -1; } renderTable(); }
function sortVal(o, k) {
  if (k === 'name') return o.name.toLowerCase();
  if (k === 'status') return o.missing ? 3 : o.unused ? 2 : o.state ? 1 : 0;
  if (k === 'total_refs') return o.total_refs;
  return o.counts[k] || 0;
}

function renderTable() {
  var q = document.getElementById('search').value.trim().toLowerCase();
  var unusedOnly = document.getElementById('unused-only').checked;
  var rows;
  if (tab === 'top') {
    var ids = {}; DATA.top.forEach(function (t, i) { ids[t.id] = i; });
    rows = DATA.objects.filter(function (o) { return ids[o.id] !== undefined; }).sort(function (a, b) { return ids[a.id] - ids[b.id]; });
  } else {
    rows = DATA.objects.filter(function (o) { return o.kind === tab; });
  }
  if (q) rows = rows.filter(function (o) { return o._hay.indexOf(q) >= 0; });
  if (unusedOnly) rows = rows.filter(function (o) { return o.unused; });
  if (tab !== 'top') rows.sort(function (a, b) { var x = sortVal(a, sortKey), y = sortVal(b, sortKey); return (x < y ? -1 : x > y ? 1 : 0) * sortDir || a.name.localeCompare(b.name); });

  var th = tab === 'top' ? '<th class="px-3 py-2">Kind</th>' : '';
  COLS.forEach(function (c) {
    var arrow = sortKey === c.k ? (sortDir < 0 ? ' ▼' : ' ▲') : '';
    th += '<th class="px-3 py-2 sortable' + (c.n ? ' text-right' : '') + '" onclick="setSort(\'' + c.k + '\')">' + c.t + arrow + '</th>';
  });
  document.getElementById('thead').innerHTML = th;

  var html = '';
  rows.forEach(function (o) {
    html += '<tr class="row border-t border-gray-700/50' + (sel === o.id ? ' sel' : '') + '" onclick="select(\'' + esc(o.id) + '\')">';
    if (tab === 'top') html += '<td class="px-3 py-2 text-gray-400">' + esc(kindName(o.kind)) + '</td>';
    html += '<td class="px-3 py-2 text-white">' + esc(o.name) + (o.kind === 'label_group' && o.members ? ' <span class="text-xs text-gray-500">(' + o.members.labels + ' labels, ' + o.members.sub_groups + ' groups)</span>' : '') + '</td>';
    html += '<td class="px-3 py-2 text-right">' + o.counts.rules + '</td>';
    html += '<td class="px-3 py-2 text-right">' + o.counts.boundaries + '</td>';
    html += '<td class="px-3 py-2 text-right">' + (o.kind === 'label' || o.kind === 'label_group' ? o.counts.label_groups : '<span class="text-gray-600">—</span>') + '</td>';
    html += '<td class="px-3 py-2 text-right">' + (o.kind === 'label' ? o.counts.other + o.counts.pairing_profiles : '<span class="text-gray-600">—</span>') + '</td>';
    html += '<td class="px-3 py-2 text-right">' + (o.kind === 'label' ? o.counts.workloads : '<span class="text-gray-600">—</span>') + '</td>';
    html += '<td class="px-3 py-2">' + status(o) + '</td></tr>';
  });
  document.getElementById('tbody').innerHTML = html || '<tr><td colspan="8" class="px-3 py-6 text-center text-gray-500">No objects match.</td></tr>';
  document.getElementById('count').textContent = rows.length + ' object' + (rows.length === 1 ? '' : 's');
}

function select(id) { sel = id; renderTable(); renderDetail(id); }

function renderDetail(id) {
  var o = null;
  for (var i = 0; i < DATA.objects.length; i++) if (DATA.objects[i].id === id) { o = DATA.objects[i]; break; }
  var el = document.getElementById('detail');
  if (!o) { el.innerHTML = '<div class="text-gray-500">Object no longer in the index.</div>'; return; }
  var h = '<div class="flex items-start justify-between gap-2 mb-2">'
    + '<div><div class="text-xs text-gray-500 uppercase">' + esc(kindName(o.kind)) + '</div>'
    + '<div class="text-lg font-semibold text-white break-all">' + esc(o.name) + '</div></div>'
    + '<div class="flex flex-col items-end gap-1">' + status(o) + (o.pversions.length ? '<div>' + pvChips(o.pversions) + '</div>' : '') + '</div></div>';
  if (!o.missing) h += '<div class="mb-2">' + link(o.url, 'Open in PCE ↗') + '</div>';
  else h += '<div class="mb-2 text-xs text-gray-500">Referenced by policy but not found in the fetched catalog (deleted, or in a policy version that is not indexed). ' + esc(o.href) + '</div>';
  var c = o.counts;
  h += '<div class="flex flex-wrap gap-1 mb-1">'
    + chip('c-info', c.rules + ' rule refs') + chip('c-info', c.boundaries + ' boundaries')
    + (o.kind === 'label' || o.kind === 'label_group' ? chip('c-info', c.label_groups + ' groups') : '')
    + (o.kind === 'label' ? chip('c-info', c.pairing_profiles + ' pairing profiles') + chip('c-info', c.other + ' other') + chip('c-info', c.workloads + ' workloads') : '')
    + '</div>';
  if (o.kind === 'label' && o.flags.length) h += '<div class="text-xs text-gray-500 mb-1">PCE reports usage in: ' + esc(o.flags.map(flagName).join(', ')) + '</div>';

  h += '<div class="sec"><div class="font-semibold text-white mb-1">Rules <span class="text-gray-500 font-normal">' + c.rules + '</span></div>';
  if (o.rules.length) {
    h += '<table class="w-full text-xs"><thead><tr class="text-gray-500 text-left"><th class="py-1 pr-2">Ruleset</th><th class="py-1 pr-2">#</th><th class="py-1 pr-2">How</th><th class="py-1">Policy</th></tr></thead><tbody>';
    o.rules.forEach(function (r) {
      var num = r.type === 'scope' ? chip('c-dim', 'scope') : numberText(r);
      var how = r.role === 'scope' ? (r.exclusion ? 'scope (excluded)' : 'ruleset scope') : r.role === 'consumer' ? 'source' : r.role === 'provider' ? 'destination' : 'service';
      var extra = [];
      if (r.type === 'deny') extra.push(chip('c-bad', 'deny'));
      if (r.extra_scope) extra.push(chip('c-warn', 'extra-scope'));
      Object.keys(r.enabled).forEach(function (pv) { if (!r.enabled[pv]) extra.push(chip('c-dim', 'disabled' + (r.pversions.length > 1 ? ' in ' + pv : ''))); });
      h += '<tr class="border-t border-gray-700/40"><td class="py-1 pr-2">' + link(r.ruleset_url, r.ruleset) + '</td><td class="py-1 pr-2 whitespace-nowrap">' + num + '</td>'
        + '<td class="py-1 pr-2">' + esc(how) + (extra.length ? ' ' + extra.join(' ') : '') + '</td><td class="py-1">' + pvChips(r.pversions) + '</td></tr>';
    });
    h += '</tbody></table>';
  } else h += '<div class="text-xs text-gray-500">Not referenced by any rule or ruleset scope.</div>';
  h += '</div>';

  if (o.boundaries.length) {
    h += '<div class="sec"><div class="font-semibold text-white mb-1">Enforcement boundaries <span class="text-gray-500 font-normal">' + c.boundaries + '</span></div><table class="w-full text-xs"><tbody>';
    o.boundaries.forEach(function (b) {
      var how = b.role === 'consumer' ? 'source' : b.role === 'provider' ? 'destination' : 'service';
      var dis = Object.keys(b.enabled).filter(function (pv) { return !b.enabled[pv]; });
      h += '<tr class="border-t border-gray-700/40"><td class="py-1 pr-2">' + link(b.url, b.name) + '</td><td class="py-1 pr-2">' + esc(how) + (dis.length ? ' ' + chip('c-dim', 'disabled') : '') + '</td><td class="py-1 text-right">' + pvChips(b.pversions) + '</td></tr>';
    });
    h += '</tbody></table></div>';
  }
  if (o.label_groups.length) {
    h += '<div class="sec"><div class="font-semibold text-white mb-1">' + (o.kind === 'label_group' ? 'Member of label groups' : 'Label groups') + ' <span class="text-gray-500 font-normal">' + c.label_groups + '</span></div><div class="text-xs space-y-1">';
    o.label_groups.forEach(function (g) { h += '<div>' + link(g.url, g.name) + ' ' + pvChips(g.pversions) + '</div>'; });
    h += '</div></div>';
  }
  if (o.pairing_profiles.length) {
    h += '<div class="sec"><div class="font-semibold text-white mb-1">Pairing profiles <span class="text-gray-500 font-normal">' + c.pairing_profiles + '</span></div><div class="text-xs space-y-1">';
    o.pairing_profiles.forEach(function (p) { h += '<div>' + link(p.url, p.name) + (p.enabled === false ? ' ' + chip('c-dim', 'disabled') : '') + '</div>'; });
    h += '</div></div>';
  }
  if (o.other_flags.length) {
    h += '<div class="sec"><div class="font-semibold text-white mb-1">Other references</div><div class="flex flex-wrap gap-1">';
    o.other_flags.forEach(function (f) { h += chip('c-info', flagName(f)); });
    h += '</div><div class="text-xs text-gray-500 mt-1">Reported by the PCE; open the label in the PCE for the exact objects.</div></div>';
  }
  if (o.kind === 'label') {
    h += '<div class="sec"><div class="font-semibold text-white mb-1">Workloads <span class="text-gray-500 font-normal">' + c.workloads + (c.workloads > o.workloads.sample.length ? ' · showing first ' + o.workloads.sample.length : '') + '</span></div>';
    if (o.workloads.sample.length) {
      h += '<table class="w-full text-xs"><tbody>';
      o.workloads.sample.forEach(function (w) {
        h += '<tr class="border-t border-gray-700/40"><td class="py-1 pr-2">' + link(w.url, w.name || w.hostname || w.href) + (w.hostname && w.hostname !== w.name ? ' <span class="text-gray-500">' + esc(w.hostname) + '</span>' : '') + '</td>'
          + '<td class="py-1 text-right text-gray-400">' + esc((w.enforcement_mode || '').replace(/_/g, ' ')) + (w.managed === false ? ' · unmanaged' : w.online === false ? ' · offline' : '') + '</td></tr>';
      });
      h += '</tbody></table>';
    } else h += '<div class="text-xs text-gray-500">No workloads carry this label.</div>';
    h += '</div>';
  }
  if (o.unused) h += '<div class="sec text-xs text-red-300">Nothing references this object. It is a candidate for cleanup — confirm in the PCE before deleting.</div>';
  el.innerHTML = h;
}
function numberText(r) {
  var a = r.number.active, d = r.number.draft;
  if (a && d && a !== d) return '#' + a + ' <span class="text-gray-500">(draft #' + d + ')</span>';
  return '#' + (a || d);
}

async function rebuild() {
  var btn = document.getElementById('rebuild-btn');
  btn.disabled = true; btn.textContent = 'Rebuilding...';
  var before = DATA ? DATA.generated_at : null;
  try { await fetch('api/rebuild', {method: 'POST'}); } catch (e) {}
  var tries = 0;
  var timer = setInterval(async function () {
    tries++;
    try {
      var s = await (await fetch('api/summary')).json();
      if (s.generated_at && s.generated_at !== before) { clearInterval(timer); btn.disabled = false; btn.textContent = 'Rebuild'; load(); return; }
    } catch (e) {}
    if (tries > 120) { clearInterval(timer); btn.disabled = false; btn.textContent = 'Rebuild'; }
  }, 3000);
}

load();
</script>
</body>
</html>
"""


@app.dashboard
def dashboard():
    return DASHBOARD


if __name__ == "__main__":
    app.run()
