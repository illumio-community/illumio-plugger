#!/usr/bin/env python3
"""Unit tests for ise-sync's pure ISE-ERS -> Illumio transform.

Run inside the built image:
    docker run --rm -v $PWD/test_transform.py:/app/test_transform.py \
        --entrypoint python3 ise-sync:latest /app/test_transform.py
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


# is_host_ip / host_address
check(main.is_host_ip("10.0.0.5"), "bare IP is a host")
check(main.is_host_ip("10.0.0.5/32"), "/32 is a host")
check(not main.is_host_ip("10.0.0.0/24"), "/24 is not a host")
check(not main.is_host_ip(""), "empty is not a host")
check(main.host_address("10.0.0.5/32") == "10.0.0.5", "host_address strips mask")

# mapping_to_workload — host mapping with SGT reference resolved by id
sgt_by_id = {"sgt-id-1": "Employees"}
m = {"id": "map1", "name": "finance-host", "ip": "10.1.2.3/32", "sgt": {"id": "sgt-id-1"}}
d = main.mapping_to_workload(m, sgt_by_id)
check(d is not None, "host mapping yields a workload")
check(d["ref"] == "map1", "ref is the mapping id")
check(d["interfaces"] == [{"name": "eth0", "address": "10.1.2.3"}], "interface from host ip")
check(dict(d["labels"]).get(main.SGT_LABEL_KEY) == "Employees", "sgt label resolved via id map")

# sgt name present inline on the reference
d2 = main.mapping_to_workload({"id": "m2", "ip": "10.1.2.4", "sgt": {"name": "Guests"}}, {})
check(dict(d2["labels"]).get(main.SGT_LABEL_KEY) == "Guests", "sgt label from inline name")

# subnet mapping -> skipped
check(main.mapping_to_workload({"id": "m3", "ip": "10.2.0.0/24", "sgt": {}}, {}) is None,
      "subnet mapping is skipped")

# no sgt -> workload with no labels but still valid (IP visibility)
d4 = main.mapping_to_workload({"id": "m4", "ip": "10.1.2.5"}, {})
check(d4 is not None and d4["labels"] == [], "host mapping with no sgt still yields a workload")

# signature
s1 = main.workload_signature(["/l/2", "/l/1"], [{"address": "1.1.1.1"}])
s2 = main.workload_signature(["/l/1", "/l/2"], [{"address": "1.1.1.1"}])
s3 = main.workload_signature(["/l/1"], [{"address": "2.2.2.2"}])
check(s1 == s2, "signature ignores label order")
check(s1 != s3, "signature changes with ip/labels")

# sanitize
check(main.sanitize(None, "x") == "x", "sanitize None -> default")
check(len(main.sanitize("a" * 400, "x")) == 255, "sanitize caps at 255")

print(f"\n{'PASS' if fails == 0 else 'FAIL'}: {fails} failure(s)")
raise SystemExit(1 if fails else 0)
