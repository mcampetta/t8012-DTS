import unittest

from odtslib.pwn_runtime_audit import build_enter_pwned_dfu_runtime_audit


class EnterPwnedDFURuntimeAuditTests(unittest.TestCase):
    def test_runtime_audit_reports_entry_points_and_blockers(self):
        report = build_enter_pwned_dfu_runtime_audit()
        self.assertEqual(report["step"], "enter-pwned-dfu")
        self.assertEqual(len(report["entry_points"]), 2)
        blocker_classes = {item["classification"] for item in report["blockers"]}
        self.assertIn("interpreter_missing", blocker_classes)
        self.assertIn("python2_syntax_dependency", blocker_classes)

    def test_runtime_audit_includes_key_imported_files(self):
        report = build_enter_pwned_dfu_runtime_audit()
        imported_paths = {item["path"] for item in report["imported_python_files"]}
        self.assertTrue(any(path.endswith("resources/ipwndfu8012/dfu.py") for path in imported_paths))
        self.assertTrue(any(path.endswith("resources/ipwndfu8012/usbexec.py") for path in imported_paths))
        self.assertTrue(any(path.endswith("resources/ipwndfu8012/checkm8.py") for path in imported_paths))


if __name__ == "__main__":
    unittest.main()
