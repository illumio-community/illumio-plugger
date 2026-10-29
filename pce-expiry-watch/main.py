#!/usr/bin/env python3
"""
pce-expiry-watch — warn before PCE objects expire.

Cron plugin. On each run it checks the expiry of selected PCE objects and
publishes a report (via the plugger reporting bus) for anything inside the
warning window. Each check is independently toggleable and all thresholds
are configurable via env vars.

Checks (all opt-out):
  - service accounts   (API key expiry)
  - pairing keys       (key lifespan + uses remaining)
  - PCE license        (best-effort; endpoint configurable)
  - PCE TLS cert       (notAfter on PCE_HOST:PCE_PORT, no API needed)
"""

import logging
import os
import ssl
import sys
import tempfile
from datetime import datetime, timezone

from illumio import PolicyComputeEngine

from plugger_report import publish_report

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("pce_expiry_watch")


def env_bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def env_int(name, default):
    try:
        return int(os.environ.get(name, "").strip())
    except (ValueError, TypeError):
        return default


# --- config -----------------------------------------------------------------
WARN_DAYS = env_int("WARN_DAYS", 30)
CRITICAL_DAYS = env_int("CRITICAL_DAYS", 7)
PAIRING_USES_WARN = env_int("PAIRING_USES_WARN", 5)
LICENSE_API_PATH = os.environ.get("LICENSE_API_PATH", "/license").strip() or "/license"
REPORT_ALL_CLEAR = env_bool("REPORT_ALL_CLEAR", False)

CHECK_SERVICE_ACCOUNTS = env_bool("CHECK_SERVICE_ACCOUNTS", True)
CHECK_PAIRING_KEYS = env_bool("CHECK_PAIRING_KEYS", True)
CHECK_LICENSE = env_bool("CHECK_LICENSE", True)
CHECK_TLS_CERT = env_bool("CHECK_TLS_CERT", True)

PCE_HOST = os.environ.get("PCE_HOST", "")
PCE_PORT = int(os.environ.get("PCE_PORT", "8443") or "8443")


def get_pce():
    pce = PolicyComputeEngine(
        url=os.environ["PCE_HOST"],
        port=os.environ.get("PCE_PORT", "8443"),
        org_id=os.environ.get("PCE_ORG_ID", "1"),
    )
    pce.set_credentials(
        username=os.environ["PCE_API_KEY"],
        password=os.environ["PCE_API_SECRET"],
    )
    verify = os.environ.get("PCE_TLS_SKIP_VERIFY", "true").lower() not in ("1", "true", "yes")
    pce.set_tls_settings(verify=verify)
    if not verify:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return pce


# --- helpers -----------------------------------------------------------------
def parse_dt(value):
    """Parse an ISO8601 timestamp into a tz-aware UTC datetime, or None."""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def first_dt(obj, keys):
    """Return (datetime, field_name) for the first parseable timestamp field."""
    for k in keys:
        dt = parse_dt(obj.get(k))
        if dt:
            return dt, k
    return None, None


def days_until(dt, now):
    return (dt - now).total_seconds() / 86400.0


def severity_for_days(days):
    """Map days-remaining to a report severity, or None if outside the window."""
    if days is None:
        return None
    if days <= CRITICAL_DAYS:   # includes already-expired (negative)
        return "critical"
    if days <= WARN_DAYS:
        return "warning"
    return None


def add_finding(findings, kind, name, dt, days, severity, detail):
    findings.append({
        "kind": kind,
        "name": name,
        "days": days,
        "severity": severity,
        "detail": detail,
        "expires": dt.isoformat() if dt else None,
    })


# --- checks ------------------------------------------------------------------
def check_service_accounts(pce, now, findings):
    resp = pce.get("/service_accounts", params={"max_results": 10000})
    if resp.status_code != 200:
        log.warning("service_accounts: HTTP %s — skipping (needs org-admin API perms?)",
                    resp.status_code)
        return
    accounts = resp.json()
    if not isinstance(accounts, list):
        return
    log.info("service_accounts: %d found", len(accounts))
    for sa in accounts:
        name = sa.get("name") or sa.get("href", "?")
        dt, field = first_dt(sa, ["expires_at", "expiration", "expires_on", "expired_at"])
        if not dt:
            log.debug("service account %s: no expiry field (keys: %s)", name, list(sa.keys()))
            continue
        days = days_until(dt, now)
        sev = severity_for_days(days)
        if sev:
            add_finding(findings, "service account", name, dt, days, sev,
                        f"API key expires {dt:%Y-%m-%d} ({field})")


def check_pairing_keys(pce, now, findings):
    resp = pce.get("/pairing_profiles", params={"max_results": 10000})
    if resp.status_code != 200:
        log.warning("pairing_profiles: HTTP %s — skipping", resp.status_code)
        return
    profiles = resp.json()
    if not isinstance(profiles, list):
        return
    log.info("pairing_profiles: %d found", len(profiles))
    for pp in profiles:
        name = pp.get("name") or pp.get("href", "?")

        # 1) key lifespan expiry — only if an active key has been generated
        lifespan = pp.get("key_lifespan")
        generated = parse_dt(pp.get("last_pairing_key_generated_at"))
        if isinstance(lifespan, int) and generated:
            expiry = datetime.fromtimestamp(generated.timestamp() + lifespan, tz=timezone.utc)
            days = days_until(expiry, now)
            sev = severity_for_days(days)
            if sev:
                add_finding(findings, "pairing key", name, expiry, days, sev,
                            f"active key expires {expiry:%Y-%m-%d} (lifespan {lifespan}s)")

        # 2) uses remaining — best-effort (aggregate counter; see README caveat)
        allowed = pp.get("allowed_uses_per_key")
        used = pp.get("total_use_count")
        if isinstance(allowed, int) and isinstance(used, int):
            remaining = allowed - used
            if remaining <= PAIRING_USES_WARN:
                sev = "critical" if remaining <= 0 else "warning"
                add_finding(findings, "pairing key", name, None, None, sev,
                            f"{max(remaining, 0)} of {allowed} key uses remaining")


def check_license(pce, now, findings):
    # Safety: the license object is not exposed by a stable public API on every
    # PCE version. Any of these is an expected, non-fatal "not available here":
    # the SDK raising on a 4xx/5xx, a non-200, a non-JSON body, or an unexpected
    # shape. All degrade to an INFO skip so a variant PCE never breaks the run.
    try:
        resp = pce.get(LICENSE_API_PATH)
    except Exception as e:  # noqa: BLE001 — SDK raises on non-2xx; endpoint varies by PCE
        log.info("license: not API-readable on this PCE (%s) — skipping "
                 "(set LICENSE_API_PATH to override)", e)
        return
    if getattr(resp, "status_code", None) != 200:
        log.info("license: HTTP %s at %s — skipping (set LICENSE_API_PATH to override)",
                 getattr(resp, "status_code", "?"), LICENSE_API_PATH)
        return
    try:
        lic = resp.json()
    except ValueError:
        log.info("license: non-JSON response at %s — skipping", LICENSE_API_PATH)
        return
    entries = lic if isinstance(lic, list) else [lic]
    for lc in entries:
        if not isinstance(lc, dict):
            continue
        name = lc.get("name") or lc.get("type") or "PCE license"
        dt, field = first_dt(lc, ["expiration_date", "expires_at", "expiration",
                                   "valid_until", "end_date"])
        if not dt:
            log.info("license: no expiry field found (keys: %s)", list(lc.keys()))
            continue
        days = days_until(dt, now)
        sev = severity_for_days(days)
        if sev:
            add_finding(findings, "license", name, dt, days, sev,
                        f"license expires {dt:%Y-%m-%d} ({field})")


def check_tls_cert(now, findings):
    if not PCE_HOST:
        log.warning("tls cert: PCE_HOST not set — skipping")
        return
    # Pure stdlib: fetch the peer cert (unverified, so lab/self-signed certs work)
    # and decode notAfter without a native crypto dependency.
    try:
        pem = ssl.get_server_certificate((PCE_HOST, PCE_PORT), timeout=10)
    except OSError as e:
        log.warning("tls cert: could not fetch certificate from %s:%s — %s",
                    PCE_HOST, PCE_PORT, e)
        return
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            tmp = fh.name
        cert = ssl._ssl._test_decode_cert(tmp)  # stdlib cert parser, any validity
    except Exception as e:  # noqa: BLE001 — parsing failures are non-fatal
        log.warning("tls cert: could not parse certificate — %s", e)
        return
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    not_after = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
    days = days_until(not_after, now)
    log.info("tls cert: %s:%s expires %s (%.0f days)", PCE_HOST, PCE_PORT,
             not_after.date(), days)
    sev = severity_for_days(days)
    if sev:
        add_finding(findings, "TLS cert", f"{PCE_HOST}:{PCE_PORT}", not_after, days, sev,
                    f"PCE API certificate expires {not_after:%Y-%m-%d}")


# --- reporting ---------------------------------------------------------------
def _table(rows):
    lines = ["| Type | Name | Expires in | Detail |", "|---|---|---|---|"]
    for f in rows:
        if f["days"] is None:
            when = "—"
        elif f["days"] < 0:
            when = "**expired**"
        else:
            when = f"{f['days']:.0f} days"
        lines.append(f"| {f['kind']} | {f['name']} | {when} | {f['detail']} |")
    return "\n".join(lines)


def publish(findings):
    findings.sort(key=lambda f: (f["days"] if f["days"] is not None else 1e9))
    for f in findings:
        log.info("FINDING [%s] %s — %s — %s", f["severity"], f["kind"], f["name"], f["detail"])

    crit = [f for f in findings if f["severity"] == "critical"]
    warn = [f for f in findings if f["severity"] == "warning"]

    if crit:
        publish_report(
            title=f"{len(crit)} PCE object(s) expiring critically (≤{CRITICAL_DAYS}d)",
            body="## Critical PCE expiries\n\n" + _table(crit),
            severity="critical", tags=["expiry", "pce"],
            data={"count": len(crit), "items": crit},
        )
    if warn:
        publish_report(
            title=f"{len(warn)} PCE object(s) expiring soon (≤{WARN_DAYS}d)",
            body="## Upcoming PCE expiries\n\n" + _table(warn),
            severity="warning", tags=["expiry", "pce"],
            data={"count": len(warn), "items": warn},
        )
    if not findings and REPORT_ALL_CLEAR:
        publish_report(
            title="All monitored PCE objects healthy",
            body=f"No service accounts, pairing keys, license, or TLS cert "
                 f"expiring within {WARN_DAYS} days.",
            severity="info", tags=["expiry", "pce"],
        )


def main():
    log.info("pce-expiry-watch starting (warn<=%dd, critical<=%dd)", WARN_DAYS, CRITICAL_DAYS)
    now = datetime.now(timezone.utc)
    findings = []

    need_api = CHECK_SERVICE_ACCOUNTS or CHECK_PAIRING_KEYS or CHECK_LICENSE
    pce = None
    if need_api:
        try:
            pce = get_pce()
        except KeyError as e:
            log.error("missing PCE env var %s — skipping API checks", e)

    checks = []
    if CHECK_SERVICE_ACCOUNTS:
        checks.append(("service accounts", lambda: check_service_accounts(pce, now, findings)))
    if CHECK_PAIRING_KEYS:
        checks.append(("pairing keys", lambda: check_pairing_keys(pce, now, findings)))
    if CHECK_LICENSE:
        checks.append(("license", lambda: check_license(pce, now, findings)))
    if CHECK_TLS_CERT:
        checks.append(("tls cert", lambda: check_tls_cert(now, findings)))

    if not checks:
        log.warning("no checks enabled — nothing to do")
        return 0

    errors = 0
    for label, fn in checks:
        if label != "tls cert" and pce is None:
            log.warning("%s: skipped (no PCE client)", label)
            errors += 1
            continue
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — one bad check shouldn't abort the rest
            log.error("%s: check failed — %s", label, e)
            errors += 1

    publish(findings)
    log.info("done: %d finding(s) within %d days", len(findings), WARN_DAYS)

    # fail the cron run only if every attempted check errored
    if errors and errors >= len(checks):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
