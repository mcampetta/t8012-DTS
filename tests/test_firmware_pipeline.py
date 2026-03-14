import plistlib
import unittest
import uuid
from pathlib import Path

from odtslib.firmware_manifest import load_firmware_manifest
from odtslib.firmware_pipeline import build_artifact_plan, generate_stage_results

TEST_TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


def _sample_manifest_bytes():
    return plistlib.dumps(
        {
            "ProductVersion": "6.1",
            "ProductBuildVersion": "19P647",
            "SupportedProductTypes": ["iBridge2,5"],
            "BuildIdentities": [
                {
                    "ApBoardID": "0x0C",
                    "ApChipID": "0x8012",
                    "Info": {
                        "DeviceClass": "j132ap",
                        "BuildNumber": "19P647",
                        "BuildTrain": "StarBridgeC",
                        "Variant": "Customer Erase Install (IPSW)",
                    },
                    "Manifest": {
                        "iBEC": {"Info": {"Path": "Firmware/dfu/iBEC.j132ap.RELEASE.im4p", "Personalize": True}},
                        "iBSS": {"Info": {"Path": "Firmware/dfu/iBSS.j132ap.RELEASE.im4p", "Personalize": True}},
                        "KernelCache": {"Info": {"Path": "kernelcache.release.j132", "Personalize": True}},
                        "DeviceTree": {"Info": {"Path": "Firmware/all_flash/DeviceTree.j132ap.im4p", "Personalize": True}},
                        "StaticTrustCache": {"Info": {"Path": "Firmware/j132ap.trustcache", "Personalize": True}},
                        "AOP": {"Info": {"Path": "Firmware/AOP/aopfw-t8012aop.im4p", "Personalize": True}},
                        "CallanFirmware": {"Info": {"Path": "Firmware/CallanFirmware.im4p", "Personalize": True}},
                        "Multitouch": {"Info": {"Path": "Firmware/Multitouch.im4p", "Personalize": True}},
                    },
                }
            ],
        }
    )


class FirmwarePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TEST_TMP_ROOT / f"firmware-{uuid.uuid4().hex}"
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

    def test_manifest_parses_build_identities_and_components(self):
        manifest = load_firmware_manifest(self.manifest_path)
        self.assertEqual(manifest.product_version, "6.1")
        self.assertEqual(manifest.supported_product_types, ("iBridge2,5",))
        self.assertEqual(manifest.build_identities[0].device_class, "j132ap")
        self.assertEqual(manifest.build_identities[0].component("iBEC").path, "Firmware/dfu/iBEC.j132ap.RELEASE.im4p")

    def test_artifact_plan_selects_board_specific_components(self):
        manifest = load_firmware_manifest(self.manifest_path)
        plan = build_artifact_plan(manifest, "j132ap")
        component_names = {component.logical_name for component in plan.components}
        self.assertIn("ibec", component_names)
        self.assertIn("kernelcache", component_names)
        ibec = next(component for component in plan.components if component.logical_name == "ibec")
        self.assertTrue(ibec.output_path.endswith("ibec.im4p"))

    def test_stage_results_describe_safe_pipeline(self):
        manifest = load_firmware_manifest(self.manifest_path)
        stages = generate_stage_results(manifest, "j132ap")
        self.assertEqual(stages[0].stage.name, "manifest-load")
        self.assertTrue(stages[0].stage.dry_run_safe)
        self.assertEqual(stages[-1].status, "ok")


if __name__ == "__main__":
    unittest.main()
