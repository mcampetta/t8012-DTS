import plistlib
import shutil
import unittest
import uuid
from pathlib import Path
from zipfile import ZipFile

from odtslib.payload_layout import inspect_payload_layout

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
                    },
                }
            ],
        }
    )


class PayloadLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TEST_TMP_ROOT / f"payload-layout-{uuid.uuid4().hex}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.ipsw_path = self.temp_dir / "fixture.ipsw"
        self.destination = self.temp_dir / "payload-root"
        with ZipFile(self.ipsw_path, "w") as archive:
            archive.writestr("BuildManifest.plist", _sample_manifest_bytes())
            archive.writestr("Firmware/dfu/iBEC.j152f.RELEASE.im4p", b"ibec")
            archive.writestr("Firmware/dfu/iBSS.j152f.RELEASE.im4p", b"ibss")

    def tearDown(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def test_inspect_payload_layout_reports_archive_presence(self):
        report = inspect_payload_layout(
            ipsw_path=self.ipsw_path,
            manifest_path=None,
            board_config="j152fap",
            destination_root=self.destination,
            extract=False,
        )
        self.assertTrue(report["all_components_available"])
        self.assertTrue(all(component["archive_present"] for component in report["components"]))
        self.assertTrue(all(component["action"] == "extract IPSW" for component in report["components"]))

    def test_extract_planned_payloads_writes_only_needed_files(self):
        report = inspect_payload_layout(
            ipsw_path=self.ipsw_path,
            manifest_path=None,
            board_config="j152fap",
            destination_root=self.destination,
            extract=True,
        )
        self.assertTrue((self.destination / "Firmware/dfu/iBEC.j152f.RELEASE.im4p").exists())
        self.assertTrue((self.destination / "Firmware/dfu/iBSS.j152f.RELEASE.im4p").exists())
        self.assertEqual(len(report["actions"]), 2)


if __name__ == "__main__":
    unittest.main()
