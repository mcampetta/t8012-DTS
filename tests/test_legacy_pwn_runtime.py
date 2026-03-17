import unittest
from unittest.mock import patch

from odtslib import legacy_pwn_runtime
from odtslib.legacy_pwn_runtime import build_legacy_pwn_runtime_check


class LegacyPwnRuntimeCheckTests(unittest.TestCase):
    def test_contract_keeps_fallback_candidates_when_env_is_selected(self):
        with patch.dict("os.environ", {"ODTS_LEGACY_PYTHON": "/tmp/python2.7"}, clear=False):
            with patch.object(legacy_pwn_runtime, "_resolve_interpreter") as resolve:
                resolve.side_effect = lambda ref: "/tmp/python2.7" if ref in {"/tmp/python2.7", "python2.7"} else None
                contract = legacy_pwn_runtime.inspect_legacy_python_contract()

        references = [candidate["reference"] for candidate in contract["candidates"]]
        self.assertEqual(contract["selected_interpreter"]["reference"], "/tmp/python2.7")
        self.assertIn("python2.7", references)
        self.assertIn("python2", references)

    def test_runtime_check_reports_host_state_and_export_hint(self):
        report = build_legacy_pwn_runtime_check()
        self.assertIn("contract", report)
        self.assertIn("issues", report)
        self.assertIn("suggested_export", report)
        self.assertFalse(report["preview_clean_runtime_boundary"])
        self.assertFalse(report["interpreter_ready"])
        issue_classes = {issue["classification"] for issue in report["issues"]}
        self.assertIn("missing_python2", issue_classes)
        self.assertIn("libusbfinder_packaging_issue", issue_classes)
        self.assertNotIn("missing_pyusb", issue_classes)
        self.assertNotIn("missing_libusb", issue_classes)

    def test_python2_availability_is_separate_from_import_readiness(self):
        fake_contract = {
            "contract": "explicit_legacy_python2",
            "env_var": "ODTS_LEGACY_PYTHON",
            "supported_on_modern_macos": "test",
            "selected_interpreter": {
                "reference": "/tmp/python2.7",
                "source": "env",
                "resolved_path": "/tmp/python2.7",
                "present": True,
            },
            "candidates": [
                {
                    "reference": "python2.7",
                    "source": "path",
                    "resolved_path": "/tmp/python2.7",
                    "present": True,
                }
            ],
            "runtime_ready": True,
        }
        fake_version = {"version": "Python 2.7.18", "major": 2, "minor": 7, "ok": True, "detail": None}
        fake_selected_imports = {
            "strategy": "selected_legacy_interpreter",
            "interpreter": "/tmp/python2.7",
            "checked": True,
            "modules": {
                "usb": {"ok": True, "detail": None},
                "usb.backend.libusb1": {"ok": False, "detail": "ImportError: No module named util"},
            },
            "detail": None,
        }
        fake_host_imports = {"strategy": "current_host_python", "modules": {"usb": True, "usb.backend.libusb1": True}}
        fake_packaging = {
            "host_macos_version": "26.3.1",
            "supported_versions": ["10.14"],
            "vendored_bottles_present": True,
            "host_supported_by_vendored_libusbfinder": False,
            "pyusb_available": True,
            "pyusb_libusb_backend_available": True,
            "packaging_ready": False,
            "issue": "Vendored libusbfinder/libusb assumptions are not clean for the current host runtime.",
        }
        with patch("odtslib.legacy_pwn_runtime.inspect_legacy_python_contract", return_value=fake_contract):
            with patch("odtslib.legacy_pwn_runtime._interpreter_version", return_value=fake_version):
                with patch("odtslib.legacy_pwn_runtime._safe_import_check_current_host", return_value=fake_host_imports):
                    with patch("odtslib.legacy_pwn_runtime._safe_import_check_selected_interpreter", return_value=fake_selected_imports):
                        with patch("odtslib.legacy_pwn_runtime.inspect_libusb_packaging", return_value=fake_packaging):
                            report = build_legacy_pwn_runtime_check()
        self.assertTrue(report["python2_7_available"])
        self.assertTrue(report["interpreter_ready"])
        self.assertTrue(report["module_import_ready"])
        self.assertFalse(report["libusb_backend_ready"])
        self.assertFalse(report["preview_clean_runtime_boundary"])
        issue_classes = {issue["classification"] for issue in report["issues"]}
        self.assertIn("missing_libusb", issue_classes)


if __name__ == "__main__":
    unittest.main()
