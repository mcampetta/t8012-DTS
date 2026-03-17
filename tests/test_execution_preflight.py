import plistlib
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from odtslib.device_state import DeviceStateReport, ToolProbe
from odtslib.execution_preflight import build_execution_graph, build_execution_preflight
from odtslib.firmware_manifest import load_firmware_manifest

TEST_TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


def _sample_manifest_bytes():
    return plistlib.dumps(
        {
            "ProductVersion": "6.1",
            "ProductBuildVersion": "19P647",
            "SupportedProductTypes": ["iBridge2,14"],
            "BuildIdentities": [
                {
                    "ApBoardID": "0x3A",
                    "ApChipID": "0x8012",
                    "Info": {
                        "DeviceClass": "j152fap",
                        "BuildNumber": "19P647",
                        "BuildTrain": "StarBridgeC",
                        "Variant": "Customer Erase Install (IPSW)",
                    },
                    "Manifest": {
                        "iBEC": {"Info": {"Path": "Firmware/dfu/iBEC.j152f.RELEASE.im4p", "Personalize": True}},
                        "iBSS": {"Info": {"Path": "Firmware/dfu/iBSS.j152f.RELEASE.im4p", "Personalize": True}},
                        "KernelCache": {"Info": {"Path": "kernelcache.release.ibridge2p", "Personalize": True}},
                        "DeviceTree": {"Info": {"Path": "Firmware/all_flash/DeviceTree.j152fap.im4p", "Personalize": True}},
                        "StaticTrustCache": {"Info": {"Path": "Firmware/j152fap.trustcache", "Personalize": True}},
                        "AOP": {"Info": {"Path": "Firmware/AOP/aopfw-t8012aop.im4p", "Personalize": True}},
                        "Multitouch": {"Info": {"Path": "Firmware/J152f_Multitouch.im4p", "Personalize": True}},
                    },
                }
            ],
        }
    )


def _device_report() -> DeviceStateReport:
    return DeviceStateReport(
        state="identifiers_ready",
        meaning="ok",
        evidence=["connected"],
        identifiers={
            "ECID": "0x1234",
            "BDID": "0x3a",
            "CPID": "0x8012",
            "PRODUCT": "iBridge2,14",
            "MODEL": "j152fap",
            "MODE": "Recovery",
        },
        tools=[
            ToolProbe(
                tool="irecovery",
                path="/opt/homebrew/bin/irecovery",
                success=True,
                stdout="",
                stderr="",
                returncode=0,
                detail="query succeeded",
                selected_candidate="system",
                candidates=[],
            )
        ],
        likely_next_step="next",
        likely_failure_causes=["none"],
        compatible_with_later_stages=True,
    )


class ExecutionPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TEST_TMP_ROOT / f"preflight-{uuid.uuid4().hex}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.temp_dir / "BuildManifest.plist"
        self.manifest_path.write_bytes(_sample_manifest_bytes())

    def tearDown(self):
        if self.temp_dir.exists():
            for path in sorted(self.temp_dir.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            self.temp_dir.rmdir()

    def test_execution_graph_uses_connected_device_model_when_board_not_supplied(self):
        manifest = load_firmware_manifest(self.manifest_path)
        with patch("odtslib.execution_preflight.collect_device_state_report", return_value=_device_report()):
            graph = build_execution_graph(manifest, None)
        self.assertEqual(graph["board_config"], "j152fap")
        self.assertEqual(graph["identity"]["board_id"], "0x3A")
        self.assertEqual(graph["device_context"]["identifiers"]["MODEL"], "j152fap")

    def test_preflight_reports_missing_signing_material_as_blocker(self):
        manifest = load_firmware_manifest(self.manifest_path)
        fake_tool_report = [{"name": "irecovery", "runnable": True, "path": "/opt/homebrew/bin/irecovery"}]
        with patch("odtslib.execution_preflight.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.execution_preflight._tool_report", return_value=fake_tool_report):
                with patch("odtslib.execution_preflight._touchpoints", return_value=[]):
                    with patch("odtslib.execution_preflight.SHSH_PATH", self.temp_dir / "missing.shsh"):
                        preflight = build_execution_preflight(manifest, None)
        self.assertFalse(preflight["ready_for_live_execution"])
        self.assertTrue(any("signing material missing" in blocker for blocker in preflight["blockers"]))

    def test_preflight_exposes_readiness_summary_and_first_execution_step(self):
        manifest = load_firmware_manifest(self.manifest_path)
        fake_tool_report = [{"name": "irecovery", "runnable": True, "path": "/opt/homebrew/bin/irecovery"}]
        with patch("odtslib.execution_preflight.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.execution_preflight._tool_report", return_value=fake_tool_report):
                with patch("odtslib.execution_preflight._touchpoints", return_value=[]):
                    with patch("odtslib.execution_preflight.LOCAL_IPSW_DIR", self.temp_dir / "empty-ipsw"):
                        preflight = build_execution_preflight(manifest, None)
        self.assertIn("readiness", preflight)
        self.assertEqual(preflight["readiness"]["first_execution_step_name"], "enter-pwned-dfu")
        self.assertEqual(preflight["readiness"]["first_execution_step_classification"], "unverified")
        self.assertEqual(preflight["readiness"]["level"], "ready for planning only")
        self.assertFalse(preflight["readiness"]["only_blocker_is_missing_payload_material"])
        self.assertFalse(preflight["readiness"]["would_valid_local_payloads_enable_live_step_testing"])

    def test_preflight_emits_unresolved_payload_analysis(self):
        manifest = load_firmware_manifest(self.manifest_path)
        fake_tool_report = [{"name": "irecovery", "runnable": True, "path": "/opt/homebrew/bin/irecovery"}]
        with patch("odtslib.execution_preflight.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.execution_preflight._tool_report", return_value=fake_tool_report):
                with patch("odtslib.execution_preflight._touchpoints", return_value=[]):
                    with patch("odtslib.execution_preflight.LOCAL_IPSW_DIR", self.temp_dir / "empty-ipsw"):
                        preflight = build_execution_preflight(manifest, None)
        self.assertIn("unresolved_payloads", preflight)
        self.assertTrue(preflight["unresolved_payloads"])
        self.assertEqual(preflight["unresolved_payloads"][0]["root_cause_category"], "missing local files")
        self.assertEqual(preflight["unresolved_payloads"][0]["remediation_action"], "extract IPSW")


if __name__ == "__main__":
    unittest.main()
