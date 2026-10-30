"""Tests for plugger_sdk.py. Run: python3 -m unittest plugin-templates/test_plugger_sdk.py"""

import os
import re
import sys
import unittest
from datetime import datetime
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import plugger_sdk  # noqa: E402
from plugger_sdk import Plugin, format_uptime  # noqa: E402

PAGE = "<!doctype html><html><head><title>x</title></head><body><span data-plugger-uptime></span></body></html>"


class FormatUptimeTest(unittest.TestCase):
    def test_formats(self):
        cases = {
            0: "0s",
            45.9: "45s",
            60: "1m",
            14 * 60 + 59: "14m",
            3 * 3600 + 14 * 60: "3h 14m",
            3 * 3600: "3h 0m",
            2 * 86400 + 3 * 3600 + 14 * 60: "2d 3h 14m",
            86400: "1d 0h 0m",
        }
        for seconds, want in cases.items():
            self.assertEqual(format_uptime(seconds), want, seconds)

    def test_negative_clamps_to_zero(self):
        self.assertEqual(format_uptime(-5), "0s")


class PluginUptimeTest(unittest.TestCase):
    def test_uptime_counts_from_construction(self):
        with mock.patch.object(plugger_sdk.time, "monotonic", return_value=1000.0):
            app = Plugin("p")
        with mock.patch.object(plugger_sdk.time, "monotonic", return_value=1000.0 + 3 * 3600 + 14 * 60):
            self.assertEqual(app.uptime_seconds, 3 * 3600 + 14 * 60)
            self.assertEqual(app.uptime, "3h 14m")

    def test_started_at_is_utc_iso(self):
        app = Plugin("p")
        self.assertTrue(app.started_at.endswith("Z"), app.started_at)
        datetime.strptime(app.started_at, "%Y-%m-%dT%H:%M:%SZ")

    def test_health_payload_includes_uptime(self):
        app = Plugin("p")
        app.state["k"] = 1
        h = app._health()
        self.assertEqual(h["status"], "healthy")
        self.assertEqual(h["plugin"], "p")
        self.assertEqual(h["state_keys"], ["k"])
        self.assertEqual(h["started_at"], app.started_at)
        self.assertIsInstance(h["uptime_seconds"], int)


class InjectionTest(unittest.TestCase):
    def test_injects_uptime_meta_and_script(self):
        app = Plugin("p")
        out = app._render_dashboard_html(PAGE)
        m = re.search(r'<meta name="plugger-uptime" content="(\d+)" data-started-at="([^"]+)">', out)
        self.assertIsNotNone(m, out[:400])
        self.assertEqual(m.group(2), app.started_at)
        self.assertIn("data-plugger-uptime-script", out)
        self.assertIn("data-plugger-theme", out)
        # injected into <head>, page body untouched
        self.assertLess(out.index("plugger-uptime"), out.index("</head>"))
        self.assertIn("<span data-plugger-uptime></span>", out)

    def test_injection_is_idempotent(self):
        app = Plugin("p")
        once = app._render_dashboard_html(PAGE)
        self.assertEqual(app._render_dashboard_html(once), once)

    def test_disabled_injection_leaves_page_alone(self):
        app = Plugin("p", inject_theme=False)
        self.assertEqual(app._render_dashboard_html(PAGE), PAGE)

    def test_non_html_left_alone(self):
        app = Plugin("p")
        self.assertEqual(app._render_dashboard_html("plain text"), "plain text")


if __name__ == "__main__":
    unittest.main()
