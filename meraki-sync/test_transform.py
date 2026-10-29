#!/usr/bin/env python3
"""Unit tests for meraki-sync's pure Meraki-client -> Illumio-workload transform.

Run inside the built image (deps present):
    docker run --rm -v $PWD/test_transform.py:/app/test_transform.py \
        --entrypoint python3 meraki-sync:latest /app/test_transform.py
"""
import main

fails = 0


def check(cond, msg):
    global fails
    if not cond:
        fails += 1
        print(f"FAIL: {msg}")
    else:
        print(f"ok:   {msg}")


# Full client -> workload
c = {"id": "k74272", "mac": "aa:bb:cc:dd:ee:ff", "description": "Reception-iPad",
     "ip": "10.20.0.42", "deviceTypePrediction": "Apple iPad", "manufacturer": "Apple"}
d = main.desired_workload(c, "HQ-Floor2")
check(d is not None, "full client yields a workload")
check(d["ref"] == "k74272", "ref prefers Meraki client id")
check(d["name"] == "Reception-iPad", "name from description")
check(dict(d["labels"]).get("loc") == "HQ-Floor2", "loc label = network name")
check(dict(d["labels"]).get("role") == "Apple iPad", "role from deviceTypePrediction")
check(d["interfaces"] == [{"name": "eth0", "address": "10.20.0.42"}], "interface from client ip")

# No identity -> skipped
check(main.desired_workload({"description": "ghost"}, "HQ") is None,
      "client with no id/mac is skipped")

# mac fallback for ref, role fallback chain, no-ip
c2 = {"mac": "11:22:33:44:55:66", "manufacturer": "Axis", "os": "Linux"}
d2 = main.desired_workload(c2, "Branch")
check(d2["ref"] == "11:22:33:44:55:66", "ref falls back to mac")
check(dict(d2["labels"]).get("role") == "Axis", "role falls back to manufacturer")
check(d2["interfaces"] == [], "no interface when client has no ip")
check(d2["name"] == "11:22:33:44:55:66", "name falls back to mac")

# role last-resort
check(main.client_role({}) == "meraki-client", "role last-resort is meraki-client")

# signature is order-independent and ip-sensitive
s1 = main.workload_signature(["/l/2", "/l/1"], [{"address": "1.1.1.1"}])
s2 = main.workload_signature(["/l/1", "/l/2"], [{"address": "1.1.1.1"}])
s3 = main.workload_signature(["/l/1", "/l/2"], [{"address": "2.2.2.2"}])
check(s1 == s2, "signature ignores label order")
check(s1 != s3, "signature changes when ip changes")

# sanitize caps + default
check(main.sanitize(None, "x") == "x", "sanitize None -> default")
check(main.sanitize("  ", "x") == "x", "sanitize blank -> default")
check(len(main.sanitize("a" * 400, "x")) == 255, "sanitize caps length at 255")

print(f"\n{'PASS' if fails == 0 else 'FAIL'}: {fails} failure(s)")
raise SystemExit(1 if fails else 0)
