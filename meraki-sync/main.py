#!/usr/bin/env python3
"""
meraki-sync — import Cisco Meraki clients into Illumio as unmanaged workloads.

Phase 1 (visibility): a daemon plugin that periodically pulls the clients Meraki
sees (the IoT / BYOD / branch devices Illumio can't put a VEN on) and represents
them in the PCE as labeled unmanaged workloads, so they appear in the map and can
be scoped by policy later. A dashboard shows what was discovered and the sync plan.

Safe by default: DRY_RUN=true logs/reports/shows what it *would* sync without
writing anything. Set DRY_RUN=false to create/update workloads.

Idempotent: every synced workload carries external_data_set=meraki-sync and
external_data_reference=<meraki client id>, so re-runs update in place (and never
touch VEN-managed or hand-created workloads).
"""

import html as html_lib
import os
from datetime import datetime, timezone

from plugger_sdk import Plugin

app = Plugin("meraki-sync")


def env_bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    try:
        return int(os.environ.get(name, "").strip())
    except (ValueError, TypeError):
        return default


# --- config -----------------------------------------------------------------
MERAKI_API_KEY = os.environ.get("MERAKI_API_KEY", "").strip()
MERAKI_ORG_ID = os.environ.get("MERAKI_ORG_ID", "").strip()
MERAKI_NETWORK_IDS = [n.strip() for n in os.environ.get("MERAKI_NETWORK_IDS", "").split(",") if n.strip()]
CLIENT_TIMESPAN = env_int("CLIENT_TIMESPAN", 86400)
MAX_CLIENTS_PER_NETWORK = env_int("MAX_CLIENTS_PER_NETWORK", 5000)
EXTERNAL_DATA_SET = os.environ.get("EXTERNAL_DATA_SET", "meraki-sync").strip() or "meraki-sync"
DRY_RUN = env_bool("DRY_RUN", True)
APP_LABEL = os.environ.get("APP_LABEL", "").strip()

BATCH = 500  # workloads per bulk op (PCE caps at 1000)


# --- Meraki client -> Illumio workload (pure, unit-tested) -------------------
def sanitize(value, default):
    if value is None:
        return default
    v = str(value).strip()
    return v[:255] if v else default


def client_reference(client):
    return sanitize(client.get("id") or client.get("mac"), "")


def client_name(client):
    return sanitize(
        client.get("description") or client.get("dhcpHostname")
        or client.get("mac") or client.get("id"),
        "meraki-client",
    )


def client_role(client):
    return sanitize(
        client.get("deviceTypePrediction") or client.get("manufacturer")
        or client.get("os"),
        "meraki-client",
    )


def client_interfaces(client):
    ip = client.get("ip")
    return [{"name": "eth0", "address": str(ip)}] if ip else []


def desired_workload(client, network_name):
    """Pure transform: Meraki client -> desired PCE workload (None if no identity)."""
    ref = client_reference(client)
    if not ref:
        return None
    labels = [("loc", sanitize(network_name, "meraki")), ("role", client_role(client))]
    if APP_LABEL:
        labels.append(("app", APP_LABEL))
    return {
        "ref": ref,
        "name": client_name(client),
        "hostname": client_name(client),
        "interfaces": client_interfaces(client),
        "labels": labels,
    }


def workload_signature(labels_hrefs, interfaces):
    ips = sorted(i.get("address", "") for i in interfaces)
    return (tuple(sorted(labels_hrefs)), tuple(ips))


# --- Meraki fetch ------------------------------------------------------------
def fetch_meraki_clients():
    """Return (network_name, client) pairs from Meraki (needs network access)."""
    import meraki
    dashboard = meraki.DashboardAPI(MERAKI_API_KEY, suppress_logging=True,
                                    print_console=False, maximum_retries=3)
    org_id = MERAKI_ORG_ID
    if not org_id:
        orgs = dashboard.organizations.getOrganizations()
        if len(orgs) != 1:
            raise RuntimeError(f"MERAKI_ORG_ID not set and the key sees {len(orgs)} orgs")
        org_id = orgs[0]["id"]
        app.log.info("using Meraki org %s (%s)", org_id, orgs[0].get("name"))

    networks = dashboard.organizations.getOrganizationNetworks(org_id, total_pages="all")
    if MERAKI_NETWORK_IDS:
        networks = [n for n in networks if n["id"] in MERAKI_NETWORK_IDS]
    app.log.info("scanning %d Meraki network(s)", len(networks))

    pairs = []
    for net in networks:
        try:
            clients = dashboard.networks.getNetworkClients(
                net["id"], timespan=CLIENT_TIMESPAN, total_pages="all", perPage=1000)
        except Exception as e:  # noqa: BLE001 — one bad network shouldn't abort the sync
            app.log.warning("network %s (%s): client fetch failed — %s",
                            net["id"], net.get("name"), e)
            continue
        clients = clients[:MAX_CLIENTS_PER_NETWORK]
        app.log.info("network %s: %d clients", net.get("name"), len(clients))
        for c in clients:
            pairs.append((net.get("name", "meraki"), c))
    return pairs


# --- sync (poll) -------------------------------------------------------------
@app.poll(interval_env="POLL_INTERVAL", default=21600)  # every 6h
def sync(pce):
    if not MERAKI_API_KEY:
        app.log.error("MERAKI_API_KEY is required")
        app.update_state({"error": "MERAKI_API_KEY is required"})
        return

    try:
        pairs = fetch_meraki_clients()
    except Exception as e:  # noqa: BLE001
        app.log.error("Meraki fetch failed: %s", e)
        app.update_state({"error": f"Meraki fetch failed: {e}",
                          "last_sync": datetime.now(timezone.utc).isoformat()})
        app.report(title="meraki-sync: Meraki fetch failed", body=str(e),
                   severity="warning", tags=["meraki"])
        return

    desired, skipped = [], 0
    for network_name, client in pairs:
        d = desired_workload(client, network_name)
        if d is None:
            skipped += 1
        else:
            desired.append(d)
    app.log.info("discovered %d usable client(s), %d skipped", len(desired), skipped)

    if DRY_RUN:
        _dry_run(pce, desired, skipped)
    else:
        _apply(pce, desired, skipped)


def _existing_by_reference(pce):
    resp = pce.get("/workloads", params={"external_data_set": EXTERNAL_DATA_SET,
                                         "max_results": 10000})
    out = {}
    for wl in (resp.json() if resp.status_code == 200 else []):
        ref = wl.get("external_data_reference")
        if ref:
            out[ref] = wl
    return out


def _dry_run(pce, desired, skipped):
    try:
        existing = _existing_by_reference(pce)
    except Exception as e:  # noqa: BLE001
        app.log.warning("dry-run: could not read existing workloads — %s", e)
        existing = {}
    would_create = sum(1 for d in desired if d["ref"] not in existing)
    would_update = len(desired) - would_create
    app.log.info("DRY RUN — would create %d, update up to %d (set DRY_RUN=false to apply)",
                 would_create, would_update)
    _save_state(desired, skipped, dry_run=True, created=would_create,
                updated=would_update, errors=0)
    app.report(
        title=f"meraki-sync (dry run): {len(desired)} Meraki client(s) discovered",
        body=f"**Dry run** — no workloads written (set `DRY_RUN=false` to apply).\n\n"
             f"- discovered: {len(desired)}\n- would create: {would_create}\n"
             f"- would update: {would_update}\n- skipped: {skipped}",
        severity="info", tags=["meraki", "discovery", "dry-run"],
        data={"discovered": len(desired), "would_create": would_create,
              "would_update": would_update, "skipped": skipped, "dry_run": True},
    )


def _apply(pce, desired, skipped):
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
            "name": d["name"], "hostname": d["hostname"],
            "interfaces": d["interfaces"],
            "labels": [{"href": h} for h in d["label_hrefs"]],
            "external_data_set": EXTERNAL_DATA_SET,
            "external_data_reference": d["ref"],
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

    app.log.info("plan: create %d, update %d, unchanged %d", len(to_create), len(to_update),
                 len(desired) - len(to_create) - len(to_update))
    errors = _bulk(pce, "bulk_create", to_create) + _bulk(pce, "bulk_update", to_update)

    _save_state(desired, skipped, dry_run=False, created=len(to_create),
                updated=len(to_update), errors=errors)
    app.report(
        title=f"meraki-sync: {len(to_create)} new, {len(to_update)} updated "
              f"({len(desired)} Meraki clients)",
        body=f"- discovered: {len(desired)}\n- created: {len(to_create)}\n"
             f"- updated: {len(to_update)}\n- skipped: {skipped}\n- errors: {errors}",
        severity="warning" if errors else "info", tags=["meraki", "discovery"],
        data={"discovered": len(desired), "created": len(to_create),
              "updated": len(to_update), "skipped": skipped, "errors": errors},
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


def _save_state(desired, skipped, dry_run, created, updated, errors):
    devices = []
    for d in desired[:100]:
        labels = dict(d["labels"])
        devices.append({
            "name": d["name"], "loc": labels.get("loc", ""), "role": labels.get("role", ""),
            "ip": d["interfaces"][0]["address"] if d["interfaces"] else "",
        })
    app.update_state({
        "last_sync": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run, "discovered": len(desired), "created": created,
        "updated": updated, "skipped": skipped, "errors": errors,
        "devices": devices, "error": None,
    })


# --- API: on-demand sync -----------------------------------------------------
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
    mode_badge = ('<span class="px-2 py-0.5 rounded text-xs bg-amber-500/20 text-amber-300">DRY RUN</span>'
                  if dry else
                  '<span class="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-300">LIVE</span>')
    err = s.get("error")
    err_html = (f'<div class="bg-red-500/15 border border-red-500/30 text-red-300 rounded-lg p-3 mb-4">{html_lib.escape(str(err))}</div>'
                if err else "")

    def stat(label, value, color="text-white"):
        return (f'<div class="bg-dark-700 rounded-lg p-4"><div class="text-2xl font-bold {color}">{value}</div>'
                f'<div class="text-xs text-gray-400 uppercase tracking-wide">{label}</div></div>')

    stats = "".join([
        stat("Discovered", s.get("discovered", 0)),
        stat("Created" if not dry else "Would create", s.get("created", 0), "text-emerald-400"),
        stat("Updated" if not dry else "Would update", s.get("updated", 0), "text-sky-400"),
        stat("Skipped", s.get("skipped", 0), "text-gray-400"),
        stat("Errors", s.get("errors", 0), "text-red-400" if s.get("errors") else "text-white"),
    ])

    rows = ""
    for d in s.get("devices", []):
        rows += (f'<tr class="border-t border-gray-700">'
                 f'<td class="py-2 px-3">{html_lib.escape(str(d.get("name","")))}</td>'
                 f'<td class="py-2 px-3">{html_lib.escape(str(d.get("loc","")))}</td>'
                 f'<td class="py-2 px-3">{html_lib.escape(str(d.get("role","")))}</td>'
                 f'<td class="py-2 px-3 font-mono text-xs">{html_lib.escape(str(d.get("ip","")))}</td></tr>')
    if not rows:
        rows = '<tr><td colspan="4" class="py-6 px-3 text-center text-gray-500">No sync has run yet.</td></tr>'

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Meraki Sync</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={{darkMode:'class',theme:{{extend:{{colors:{{dark:{{900:'#11111b',800:'#1e1e2e',700:'#313244'}}}}}}}}}};</script>
</head>
<body class="bg-dark-900 text-gray-200 min-h-screen">
<link rel="stylesheet" href="/brand/style.css" onerror="this.remove()">
<div class="max-w-5xl mx-auto px-4 py-8">
  <div class="flex items-center justify-between mb-2">
    <h1 class="text-2xl font-bold text-white">Meraki Sync {mode_badge}</h1>
    <button onclick="fetch('api/sync',{{method:'POST'}}).then(()=>setTimeout(()=>location.reload(),1500))"
            class="bg-sky-600 hover:bg-sky-500 text-white text-sm px-4 py-2 rounded-lg">Sync now</button>
  </div>
  <p class="text-sm text-gray-400 mb-6">Cisco Meraki clients imported into Illumio as unmanaged workloads · last sync: {html_lib.escape(str(last))}</p>
  {err_html}
  <div class="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-8">{stats}</div>
  <h2 class="text-lg font-semibold text-white mb-3">Discovered devices <span class="text-sm text-gray-500">(up to 100)</span></h2>
  <div class="overflow-x-auto bg-dark-800 rounded-xl border border-gray-700">
    <table class="w-full text-sm text-left"><thead class="text-gray-400 text-xs uppercase">
      <tr><th class="py-2 px-3">Name</th><th class="py-2 px-3">loc</th><th class="py-2 px-3">role</th><th class="py-2 px-3">IP</th></tr>
    </thead><tbody>{rows}</tbody></table>
  </div>
</div>
</body></html>"""


if __name__ == "__main__":
    app.run()
