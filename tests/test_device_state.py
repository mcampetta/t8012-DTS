import json
import unittest

from odtslib.device_state import DeviceStateName, classify_device_state


class DeviceStateTests(unittest.TestCase):
    def test_identifiers_ready_when_ecid_and_bdid_present(self):
        state = classify_device_state({"ECID": "0x1234", "BDID": "0x0C"}, True)
        self.assertEqual(state, DeviceStateName.IDENTIFIERS_READY)

    def test_partial_when_only_one_identifier_present(self):
        state = classify_device_state({"ECID": "0x1234"}, True)
        self.assertEqual(state, DeviceStateName.IDENTIFIERS_PARTIAL)

    def test_no_device_when_tool_succeeds_but_no_data(self):
        state = classify_device_state({}, True)
        self.assertEqual(state, DeviceStateName.NO_DEVICE)

    def test_tool_failure_maps_to_tool_comm_failure(self):
        state = classify_device_state({}, False)
        self.assertEqual(state, DeviceStateName.TOOL_COMM_FAILURE)

    def test_json_output_shape_is_machine_readable(self):
        payload = {
            "state": DeviceStateName.IDENTIFIERS_READY.value,
            "evidence": ["ECID detected"],
            "identifiers": {"ECID": "0x1234"},
        }
        parsed = json.loads(json.dumps(payload))
        self.assertEqual(parsed["state"], "identifiers_ready")
        self.assertIn("evidence", parsed)
        self.assertIn("identifiers", parsed)


if __name__ == "__main__":
    unittest.main()
