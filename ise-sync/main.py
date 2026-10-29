#!/usr/bin/env python3
"""
ise-sync — bridge Cisco ISE identity/TrustSec context into Illumio.

Phase 1 (visibility, ERS): a daemon that polls Cisco ISE over the ERS API and
mirrors TrustSec context into the PCE:

  1. SGT definitions  -> Illumio labels in a dedicated `sgt` dimension
                         (a shared segmentation taxonomy with TrustSec).
  2. Host IP-SGT maps  -> Illumio unmanaged workloads (interface + sgt label),
                         for the single-host (/32) static mappings ISE knows.

Read-only on ISE, dry-run-by-default on the PCE. Idempotent via
external_data_set=ise-sync + external_data_reference. Richer endpoint/identity
ingest and dynamic IP<->SGT bindings require pxGrid (a later phase).
"""

import html as html_lib
import os
from datetime import datetime, timezone

import requests

from plugger_sdk import Plugin

app = Plugin("ise-sync")


def env_bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    try:
        return int(os.environ.get(name, "").strip())
    except (ValueError, TypeError):
        return default


# --- config -----------------------------------------------------------------
ISE_HOST = os.environ.get("ISE_HOST", "").strip()
ISE_PORT = os.environ.get("ISE_PORT", "9060").strip() or "9060"
ISE_ERS_USER = os.environ.get("ISE_ERS_USER", "").strip()
ISE_ERS_PASSWORD = os.environ.get("ISE_ERS_PASSWORD", "")
ISE_VERIFY = os.environ.get("ISE_TLS_SKIP_VERIFY", "true").lower() not in ("1", "true", "yes")

SGT_LABEL_KEY = os.environ.get("SGT_LABEL_KEY", "sgt").strip() or "sgt"
IMPORT_SGTS = env_bool("IMPORT_SGTS", True)
IMPORT_IP_SGT = env_bool("IMPORT_IP_SGT", True)
MAX_SGTS = env_int("MAX_SGTS", 2000)
MAX_MAPPINGS = env_int("MAX_MAPPINGS", 10000)
EXTERNAL_DATA_SET = os.environ.get("EXTERNAL_DATA_SET", "ise-sync").strip() or "ise-sync"
DRY_RUN = env_bool("DRY_RUN", True)

BATCH = 500

if not ISE_VERIFY:
    requests.packages.urllib3.disable_warnings(  # type: ignore[attr-defined]
        requests.packages.urllib3.exceptions.InsecureRequestWarning)  # type: ignore[attr-defined]


# --- pure transforms (unit-tested) ------------------------------------------
def sanitize(value, default):
    if value is None:
        return default
    v = str(value).strip()
    return v[:255] if v else default


def is_host_ip(ip):
    """True for a single host address (no CIDR, or /32)."""
    if not ip:
        return False
    ip = str(ip).strip()
    if "/" not in ip:
        return True
    addr, _, mask = ip.partition("/")
    return mask.strip() == "32"


def host_address(ip):
    return str(ip).split("/")[0].strip()


def mapping_to_workload(mapping, sgt_name_by_id):
    """Pure: an ISE sgmapping detail -> desired PCE workload, or None.

    Only single-host mappings become workloads. sgt_name_by_id resolves the
    mapping's SGT reference to its name for the label.
    """
    ip = mapping.get("ip") or mapping.get("hostIp") or mapping.get("ipAddress")
    if not is_host_ip(ip):
        return None
    addr = host_address(ip)
    sgt_ref = mapping.get("sgt") or {}
    if isinstance(sgt_ref, dict):
        sgt_id = sgt_ref.get("id") or sgt_ref.get("value")
        sgt_name = sgt_ref.get("name") or sgt_name_by_id.get(sgt_id)
    else:
        sgt_name = sgt_name_by_id.get(sgt_ref) or str(sgt_ref)
    labels = []
    if sgt_name:
        labels.append((SGT_LABEL_KEY, sanitize(sgt_name, "unknown")))
    return {
        "ref": sanitize(mapping.get("id") or addr, addr),
        "name": sanitize(mapping.get("name") or addr, addr),
        "hostname": sanitize(mapping.get("name") or addr, addr),
        "interfaces": [{"name": "eth0", "address": addr}],
        "labels": labels,
    }


def workload_signature(label_hrefs, interfaces):
    ips = sorted(i.get("address", "") for i in interfaces)
    return (tuple(sorted(label_hrefs)), tuple(ips))


# --- ISE ERS client ----------------------------------------------------------
class ISE:
    def __init__(self):
        self.base = f"https://{ISE_HOST}:{ISE_PORT}/ers/config"
        self.auth = (ISE_ERS_USER, ISE_ERS_PASSWORD)
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}

    def _get(self, path, params=None):
        r = requests.get(f"{self.base}{path}", auth=self.auth, headers=self.headers,
                         params=params, verify=ISE_VERIFY, timeout=30)
        r.raise_for_status()
        return r.json()

    def list(self, resource, cap):
        """Page through an ERS list resource, returning summary dicts (id, name)."""
        out, page = [], 1
        while len(out) < cap:
            data = self._get(f"/{resource}", params={"page": page, "size": 100})
            result = data.get("SearchResult", {})
            res = result.get("resources", [])
            if not res:
                break
            out.extend(res)
            if len(out) >= int(result.get("total", len(out))):
                break
            page += 1
        return out[:cap]

    def detail(self, resource, obj_id):
        data = self._get(f"/{resource}/{obj_id}")
        # ERS wraps detail as {"<ResourceName>": {...}} — return the inner dict.
        if isinstance(data, dict) and len(data) == 1:
            return next(iter(data.values()))
        return data


# --- sync --------------------------------------------------------------------
@app.poll(interval_env="POLL_INTERVAL", default=21600)
def sync(pce):
    if not (ISE_HOST and ISE_ERS_USER and ISE_ERS_PASSWORD):
        app.log.error("ISE_HOST, ISE_ERS_USER and ISE_ERS_PASSWORD are required")
        app.update_state({"error": "ISE connection not configured"})
        return

    ise = ISE()
    try:
        sgt_name_by_id, sgt_names = _load_sgts(ise)
    except Exception as e:  # noqa: BLE001
        app.log.error("ISE SGT fetch failed: %s", e)
        app.update_state({"error": f"ISE fetch failed: {e}",
                          "last_sync": datetime.now(timezone.utc).isoformat()})
        app.report(title="ise-sync: ISE fetch failed", body=str(e),
                   severity="warning", tags=["ise"])
        return

    desired = []
    if IMPORT_IP_SGT:
        try:
            for summ in ise.list("sgmapping", MAX_MAPPINGS):
                d = mapping_to_workload(ise.detail("sgmapping", summ["id"]), sgt_name_by_id)
                if d:
                    desired.append(d)
        except Exception as e:  # noqa: BLE001
            app.log.warning("sgmapping fetch failed: %s", e)

    app.log.info("ISE: %d SGTs, %d host IP-SGT workload(s)", len(sgt_names), len(desired))

    if DRY_RUN:
        _dry_run(pce, sgt_names, desired)
    else:
        _apply(pce, sgt_names, desired)


def _load_sgts(ise):
    """Return (id->name map, [names]) for ISE SGT definitions."""
    sgt_name_by_id, names = {}, []
    if not IMPORT_SGTS:
        return sgt_name_by_id, names
    for summ in ise.list("sgt", MAX_SGTS):
        name = summ.get("name")
        if name:
            sgt_name_by_id[summ.get("id")] = name
            names.append(name)
    return sgt_name_by_id, names


def _ensure_sgt_dimension(pce):
    """Create the custom SGT label dimension if it doesn't exist (idempotent)."""
    if SGT_LABEL_KEY in ("role", "app", "env", "loc"):
        return
    try:
        pce.post("/label_dimensions",
                 json={"key": SGT_LABEL_KEY, "display_name": SGT_LABEL_KEY.upper()})
    except Exception as e:  # noqa: BLE001 — already-exists is the common, benign case
        app.log.debug("label dimension %s: %s", SGT_LABEL_KEY, e)


def _existing_by_reference(pce):
    resp = pce.get("/workloads", params={"external_data_set": EXTERNAL_DATA_SET,
                                         "max_results": 10000})
    out = {}
    for wl in (resp.json() if resp.status_code == 200 else []):
        ref = wl.get("external_data_reference")
        if ref:
            out[ref] = wl
    return out


def _dry_run(pce, sgt_names, desired):
    try:
        existing = _existing_by_reference(pce)
    except Exception as e:  # noqa: BLE001
        app.log.warning("dry-run: could not read existing workloads — %s", e)
        existing = {}
    would_create = sum(1 for d in desired if d["ref"] not in existing)
    app.log.info("DRY RUN — %d SGT label(s), %d workload(s) (%d new) (set DRY_RUN=false to apply)",
                 len(sgt_names), len(desired), would_create)
    _save_state(sgt_names, desired, dry_run=True, sgts_synced=0,
                created=would_create, updated=len(desired) - would_create, errors=0)
    app.report(
        title=f"ise-sync (dry run): {len(sgt_names)} SGTs, {len(desired)} host mapping(s)",
        body=f"**Dry run** — nothing written (set `DRY_RUN=false` to apply).\n\n"
             f"- SGT labels: {len(sgt_names)}\n- workloads: {len(desired)} "
             f"({would_create} new)",
        severity="info", tags=["ise", "trustsec", "dry-run"],
        data={"sgts": len(sgt_names), "workloads": len(desired),
              "would_create": would_create, "dry_run": True},
    )


def _apply(pce, sgt_names, desired):
    sgts_synced = 0
    if IMPORT_SGTS and sgt_names:
        _ensure_sgt_dimension(pce)
        for name in sgt_names:
            if app.ensure_label(SGT_LABEL_KEY, sanitize(name, "unknown")):
                sgts_synced += 1

    for d in desired:
        d["label_hrefs"] = [h for h in (app.ensure_label(k, v) for k, v in d["labels"]) if h]

    try:
        existing = _existing_by_reference(pce)
    except Exception as e:  # noqa: BLE001
        app.log.error("could not read existing workloads: %s", e)
        app.update_state({"error": f"PCE read failed: {e}"})
        return

    to_create, to_update = [], []
    for d in desired:
        body = {
            "name": d["name"], "hostname": d["hostname"], "interfaces": d["interfaces"],
            "labels": [{"href": h} for h in d["label_hrefs"]],
            "external_data_set": EXTERNAL_DATA_SET, "external_data_reference": d["ref"],
        }
        cur = existing.get(d["ref"])
        if cur is None:
            to_create.append(body)
        else:
            cur_hrefs = [l.get("href") for l in cur.get("labels", []) if l.get("href")]
            if workload_signature(d["label_hrefs"], d["interfaces"]) != \
               workload_signature(cur_hrefs, cur.get("interfaces", [])):
                body["href"] = cur["href"]
                to_update.append(body)

    app.log.info("plan: %d SGT labels, create %d, update %d", sgts_synced,
                 len(to_create), len(to_update))
    errors = _bulk(pce, "bulk_create", to_create) + _bulk(pce, "bulk_update", to_update)

    _save_state(sgt_names, desired, dry_run=False, sgts_synced=sgts_synced,
                created=len(to_create), updated=len(to_update), errors=errors)
    app.report(
        title=f"ise-sync: {sgts_synced} SGT labels, {len(to_create)} new / "
              f"{len(to_update)} updated workloads",
        body=f"- SGT labels ensured: {sgts_synced}\n- workloads created: {len(to_create)}\n"
             f"- workloads updated: {len(to_update)}\n- errors: {errors}",
        severity="warning" if errors else "info", tags=["ise", "trustsec"],
        data={"sgts": sgts_synced, "created": len(to_create),
              "updated": len(to_update), "errors": errors},
    )


def _bulk(pce, op, workloads):
    errors = 0
    for i in range(0, len(workloads), BATCH):
        chunk = workloads[i:i + BATCH]
        try:
            resp = pce.put(f"/workloads/{op}", json=chunk)
        except Exception as e:  # noqa: BLE001
            app.log.error("%s failed: %s", op, e)
            errors += len(chunk)
            continue
        for item in (resp.json() if resp.status_code < 400 else []):
            if item.get("errors") or item.get("status") not in (None, "created", "updated"):
                errors += 1
                app.log.warning("%s item error: %s", op, item)
    return errors


def _save_state(sgt_names, desired, dry_run, sgts_synced, created, updated, errors):
    workloads = []
    for d in desired[:100]:
        labels = dict(d["labels"])
        workloads.append({"name": d["name"], "ip": d["interfaces"][0]["address"],
                          "sgt": labels.get(SGT_LABEL_KEY, "")})
    app.update_state({
        "last_sync": datetime.now(timezone.utc).isoformat(), "dry_run": dry_run,
        "sgt_count": len(sgt_names), "sgt_names": sgt_names[:200],
        "sgts_synced": sgts_synced, "created": created, "updated": updated,
        "errors": errors, "workloads": workloads, "error": None,
    })


@app.api("POST", "/api/sync")
def trigger_sync(request):
    app.trigger_poll()
    return {"status": "triggered"}


# --- dashboard ---------------------------------------------------------------
@app.dashboard
def dashboard():
    s = app.state
    last = s.get("last_sync") or "never"
    dry = s.get("dry_run", True)
    badge = ('<span class="px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-300">DRY RUN</span>'
             if dry else
             '<span class="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-300">LIVE</span>')
    err = s.get("error")
    err_html = (f'<div class="bg-red-500/15 border border-red-500/30 text-red-300 rounded-lg p-3 mb-4">{html_lib.escape(str(err))}</div>'
                if err else "")

    def stat(label, value, color="text-white"):
        return (f'<div class="bg-dark-700 rounded-lg p-4"><div class="text-2xl font-bold {color}">{value}</div>'
                f'<div class="text-xs text-gray-400 uppercase tracking-wide">{label}</div></div>')

    stats = "".join([
        stat("SGTs", s.get("sgt_count", 0), "text-violet-400"),
        stat("Workloads", len(s.get("workloads", []))),
        stat("Created" if not dry else "Would create", s.get("created", 0), "text-emerald-400"),
        stat("Updated" if not dry else "Would update", s.get("updated", 0), "text-sky-400"),
        stat("Errors", s.get("errors", 0), "text-red-400" if s.get("errors") else "text-white"),
    ])

    sgt_chips = "".join(
        f'<span class="inline-block bg-violet-500/15 text-violet-300 border border-violet-500/30 rounded px-2 py-0.5 text-xs mr-1 mb-1">{html_lib.escape(str(n))}</span>'
        for n in s.get("sgt_names", []))
    if not sgt_chips:
        sgt_chips = '<span class="text-gray-500 text-sm">No SGTs synced yet.</span>'

    rows = ""
    for w in s.get("workloads", []):
        rows += (f'<tr class="border-t border-gray-700">'
                 f'<td class="py-2 px-3">{html_lib.escape(str(w.get("name","")))}</td>'
                 f'<td class="py-2 px-3 font-mono text-xs">{html_lib.escape(str(w.get("ip","")))}</td>'
                 f'<td class="py-2 px-3">{html_lib.escape(str(w.get("sgt","")))}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="3" class="py-6 px-3 text-center text-gray-500">No host IP-SGT workloads yet.</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>ISE Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={{darkMode:'class',theme:{{extend:{{colors:{{dark:{{900:'#11111b',800:'#1e1e2e',700:'#313244'}}}}}}}}}};</script>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen">
<link rel="stylesheet" href="/brand/style.css" onerror="this.remove()">
<div class="max-w-5xl mx-auto px-4 py-8">
  <div class="flex items-center justify-between mb-2">
    <h1 class="text-2xl font-bold text-white">ISE Sync {badge}</h1>
    <button onclick="fetch('api/sync',{{method:'POST'}}).then(()=>setTimeout(()=>location.reload(),1500))"
            class="bg-sky-600 hover:bg-sky-500 text-white text-sm px-4 py-2 rounded-lg">Sync now</button>
  </div>
  <p class="text-sm text-gray-400 mb-6">Cisco ISE TrustSec context (SGTs + host IP-SGT mappings) mirrored into Illumio · last sync: {html_lib.escape(str(last))}</p>
  {err_html}
  <div class="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8">{stats}</div>
  <h2 class="text-lg font-semibold text-white mb-3">Security Group Tags</h2>
  <div class="bg-dark-800 rounded-xl border border-gray-700 p-4 mb-8">{sgt_chips}</div>
  <h2 class="text-lg font-semibold text-white mb-3">Host IP-SGT workloads <span class="text-sm text-gray-500">(up to 100)</span></h2>
  <div class="overflow-x-auto bg-dark-800 rounded-xl border border-gray-700">
    <table class="w-full text-sm text-left"><thead class="text-gray-400 text-xs uppercase">
      <tr><th class="py-2 px-3">Name</th><th class="py-2 px-3">IP</th><th class="py-2 px-3">SGT</th></tr>
    </thead><tbody>{rows}</tbody></table>
  </div>
</div>
</body></html>"""


if __name__ == "__main__":
    app.run()
