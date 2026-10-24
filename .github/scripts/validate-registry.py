#!/usr/bin/env python3
"""
Validate registry.json and CI build matrix consistency.

Checks:
  1. Every plugin with a plugin.yaml has a registry.json entry
  2. Every registry entry has a valid image name
  3. Registry image names match the CI build matrix output
  4. Every in-repo plugin is in the CI build matrix
  5. Registry entry fields are complete (name, version, image, description, mode)
  6. External plugins (policy-gitops, policy-workflow) use correct image prefix
"""

import json
import os
import re
import sys
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SKIP_DIRS = {
    "docs", "internal", "cmd", "bin", "vendor", ".git", ".github", ".claude",
    "plugin-templates", "node_modules", "__pycache__",
}

# Plugins that live in an external repo and are NOT built by this CI
EXTERNAL_PLUGINS = {"policy-gitops", "policy-workflow"}

# Accepted GHCR owner namespaces during the alexgoller -> illumio-community
# migration. A registry image is valid under either owner: existing plugins
# still point to alexgoller until the full cutover, while new ones (e.g.
# flowpilot) publish natively under illumio-community.
IMAGE_OWNERS = ("ghcr.io/alexgoller", "ghcr.io/illumio-community")

# Plugins whose directory exists but that are intentionally NOT yet in
# registry.json because their image can't be published/installed yet (e.g. a
# binary that isn't released). They are the validator counterpart to the CI
# EXCLUDE list in plugins.yaml. Remove from here and add the registry entry
# when the plugin becomes installable.
PENDING_PUBLISH = {"flowpilot"}


def find_plugins():
    plugins = []
    for entry in sorted(os.listdir(REPO_ROOT)):
        if entry in SKIP_DIRS or entry.startswith("."):
            continue
        plugin_dir = os.path.join(REPO_ROOT, entry)
        if os.path.isdir(plugin_dir) and os.path.exists(os.path.join(plugin_dir, "plugin.yaml")):
            plugins.append(entry)
    return plugins


def load_registry():
    path = os.path.join(REPO_ROOT, "docs", "portal", "registry.json")
    with open(path) as f:
        return json.load(f)


def main():
    plugins = find_plugins()
    registry = load_registry()

    registry_by_name = {p["name"]: p for p in registry.get("plugins", [])}

    errors = 0
    warnings = 0

    print(f"Found {len(plugins)} plugins, {len(registry_by_name)} registry entries\n")

    # Check 1: Every plugin has a registry entry (except pending-publish ones)
    for plugin in plugins:
        if plugin in registry_by_name:
            continue
        if plugin in PENDING_PUBLISH:
            print(f"⏭  {plugin}: pending publish — not yet in registry.json (intentional)")
            continue
        print(f"❌ {plugin}: missing from registry.json")
        errors += 1

    # Check 2: Every registry entry points to a real plugin
    for name in registry_by_name:
        if name not in plugins:
            print(f"⚠️  {name}: in registry but no plugin directory found")
            warnings += 1

    # Check 3: Registry image names are correct AND tagged with the plugin's
    # version. Internal plugins must use the immutable :<version> tag so the
    # registry, the image, and the installed manifest can never drift apart.
    # External plugins (built elsewhere) stay on :latest.
    for name, entry in registry_by_name.items():
        image = entry.get("image", "")
        version = entry.get("version", "")
        if name in EXTERNAL_PLUGINS:
            suffix = f"/illumio-{name}:latest"
        else:
            suffix = f"/plugger-{name}:{version}"
        expected = [owner + suffix for owner in IMAGE_OWNERS]

        if not image:
            print(f"❌ {name}: missing image field in registry")
            errors += 1
        elif image not in expected:
            print(f"❌ {name}: image must be tagged with the plugin version, under a known owner")
            print(f"     got:      {image}")
            print(f"     expected one of: {', '.join(expected)}")
            errors += 1

    # Checks 4 & 5 (static CI build matrix) are obsolete: plugin images are now
    # built by .github/workflows/plugins.yaml, which auto-discovers every dir
    # with a plugin.yaml + Dockerfile, so coverage is guaranteed by construction
    # and there is no static matrix to drift.

    # Check 6: Registry entry completeness
    required_fields = ["name", "version", "image", "description", "mode", "has_ui", "language", "tags", "homepage", "maturity"]
    for name, entry in registry_by_name.items():
        missing = [f for f in required_fields if f not in entry]
        if missing:
            print(f"⚠️  {name}: registry entry missing fields: {', '.join(missing)}")
            warnings += 1

    # Check 7: Maturity values are valid
    valid_maturity = {"example", "preview", "beta", "prototype", "production"}
    for name, entry in registry_by_name.items():
        m = entry.get("maturity", "")
        if m and m not in valid_maturity:
            print(f"❌ {name}: invalid maturity '{m}' (must be one of {valid_maturity})")
            errors += 1

    # Check 8: Registry version matches plugin.yaml version
    for plugin in plugins:
        plugin_yaml_path = os.path.join(REPO_ROOT, plugin, "plugin.yaml")
        try:
            with open(plugin_yaml_path) as f:
                pdata = yaml.safe_load(f)
            plugin_version = str(pdata.get("version", ""))
            reg_entry = registry_by_name.get(plugin, {})
            reg_version = str(reg_entry.get("version", ""))
            if plugin_version and reg_version and plugin_version != reg_version:
                print(f"⚠️  {plugin}: version mismatch — plugin.yaml={plugin_version}, registry={reg_version}")
                warnings += 1
        except Exception:
            pass

    print(f"\n{'='*60}")
    print(f"Plugins: {len(plugins)}  |  Errors: {errors}  |  Warnings: {warnings}")

    if errors > 0:
        print(f"\n❌ FAILED: {errors} error(s)")
        sys.exit(1)
    elif warnings > 0:
        print(f"\n⚠️  PASSED with {warnings} warning(s)")
    else:
        print(f"\n✅ ALL PASSED")


if __name__ == "__main__":
    main()
