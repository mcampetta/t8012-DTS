import unittest

from odtslib.setup import inspect_setup_state


class SetupTests(unittest.TestCase):
    def test_setup_state_contains_fetchable_and_manual_sections(self):
        state = inspect_setup_state()
        self.assertIn("fetchable_resources", state)
        self.assertIn("manual_resources", state)
        self.assertTrue(any(item["name"] == "img4tool_binary" for item in state["fetchable_resources"]))


if __name__ == "__main__":
    unittest.main()
