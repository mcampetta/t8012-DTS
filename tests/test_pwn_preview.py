import unittest

from odtslib.pwn_preview import build_enter_pwned_dfu_preview


class EnterPwnedDFUPreviewTests(unittest.TestCase):
    def test_preview_reports_expected_call_path_and_commands(self):
        report = build_enter_pwned_dfu_preview()
        self.assertEqual(report["step"], "enter-pwned-dfu")
        self.assertIn("resources.pwn.pwndfumode()", report["call_graph"])
        commands = {entry["name"]: entry for entry in report["commands"]}
        self.assertIn("exploit_launcher", commands)
        self.assertIn("signature_bypass_helper", commands)
        self.assertIn("resources/ipwndfu8012/ipwndfu", commands["exploit_launcher"]["command"])
        self.assertEqual(commands["signature_bypass_helper"]["probe"]["status"], "unsafe_to_probe")

    def test_preview_surfaces_modern_macos_interpreter_risks(self):
        report = build_enter_pwned_dfu_preview()
        assumptions = report["interpreter_assumptions"]
        ipwndfu = assumptions[0]
        nop_image4 = assumptions[1]
        self.assertTrue(ipwndfu["requires_python2_runtime"])
        self.assertIn("python2_print_statement", ipwndfu["python2_markers"])
        self.assertIsNone(ipwndfu["runtime_contract"]["selected_interpreter"])
        self.assertFalse(report["runtime_boundary_preview_clean"])
        self.assertTrue(nop_image4["effective_runtime_requires_python2"])


if __name__ == "__main__":
    unittest.main()
