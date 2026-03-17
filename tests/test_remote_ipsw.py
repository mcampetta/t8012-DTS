import io
import json
import plistlib
import shutil
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from odtslib.exceptions import ODTSError
from odtslib.remote_ipsw import (
    REMOTE_CACHE_NAME,
    inspect_remote_payload_layout,
    select_remote_firmware,
)

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


class _FakeRemoteZip:
    data = {
        "BuildManifest.plist": _sample_manifest_bytes(),
        "Firmware/dfu/iBEC.j152f.RELEASE.im4p": b"ibec",
        "Firmware/dfu/iBSS.j152f.RELEASE.im4p": b"ibss",
    }

    def __init__(self, url, session=None):
        self.url = url
        self.session = session

    def namelist(self):
        return list(self.data.keys())

    def read(self, path):
        return self.data[path]

    def open(self, path):
        return io.BytesIO(self.data[path])

    def close(self):
        return None


class RemoteIPSWTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TEST_TMP_ROOT / f"remote-ipsw-{uuid.uuid4().hex}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.destination = self.temp_dir / "IPSW"
        self.metadata = {
            "identifier": "iBridge2,14",
            "firmwares": [
                {
                    "version": "6.1",
                    "buildid": "19P647",
                    "url": "https://updates.cdn-apple.com/restore.ipsw",
                    "signed": True,
                },
                {
                    "version": "6.0",
                    "buildid": "19P500",
                    "url": "https://updates.cdn-apple.com/older.ipsw",
                    "signed": False,
                },
            ],
        }

    def tearDown(self):
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def test_select_remote_firmware_prefers_requested_build(self):
        selection = select_remote_firmware(self.metadata, build="19P647")
        self.assertEqual(selection.build, "19P647")
        self.assertEqual(selection.url, "https://updates.cdn-apple.com/restore.ipsw")

    def test_select_remote_firmware_raises_for_unknown_build(self):
        with self.assertRaises(ODTSError):
            select_remote_firmware(self.metadata, build="does-not-exist")

    def test_remote_payload_layout_reports_fallback_when_remote_inspection_fails(self):
        with patch("odtslib.remote_ipsw.fetch_remote_firmware_metadata", return_value=self.metadata):
            with patch("odtslib.remote_ipsw._manifest_from_remote_zip", side_effect=ODTSError("range unsupported")):
                report = inspect_remote_payload_layout(
                    device="iBridge2,14",
                    board_config="j152fap",
                    destination_root=self.destination,
                )
        self.assertFalse(report["remote_archive_inspection_succeeded"])
        self.assertEqual(report["fallback"]["classification"], "remote_unavailable_use_local_ipsw")
        self.assertIn("range unsupported", report["fallback"]["reason"])
        self.assertIsNone(report["cache_path"])

    def test_remote_payload_layout_extracts_planned_payloads_and_writes_cache(self):
        from odtslib.firmware_pipeline import load_manifest_for_planning

        manifest_path = self.temp_dir / "BuildManifest.plist"
        manifest_path.write_bytes(_sample_manifest_bytes())
        manifest = load_manifest_for_planning(manifest_path)
        names = _FakeRemoteZip("https://updates.cdn-apple.com/restore.ipsw").namelist()

        with patch("odtslib.remote_ipsw.fetch_remote_firmware_metadata", return_value=self.metadata):
            with patch("odtslib.remote_ipsw._manifest_from_remote_zip", return_value=(manifest, names)):
                with patch("odtslib.remote_ipsw.RemoteZip", _FakeRemoteZip):
                    report = inspect_remote_payload_layout(
                        device="iBridge2,14",
                        board_config="j152fap",
                        destination_root=self.destination,
                        extract=True,
                    )

        self.assertTrue(report["remote_archive_inspection_succeeded"])
        self.assertTrue(report["all_planned_payloads_available_remotely"])
        self.assertTrue((self.destination / "Firmware/dfu/iBEC.j152f.RELEASE.im4p").exists())
        self.assertTrue((self.destination / "Firmware/dfu/iBSS.j152f.RELEASE.im4p").exists())
        self.assertTrue((self.destination / "BuildManifest.plist").exists())
        cache_path = self.destination / REMOTE_CACHE_NAME
        self.assertEqual(report["cache_path"], str(cache_path))
        self.assertTrue(cache_path.exists())
        cache = json.loads(cache_path.read_text(encoding="utf-8"))
        self.assertEqual(cache["device"], "iBridge2,14")
        self.assertEqual(cache["build"], "19P647")
        self.assertEqual(cache["remote_url"], "https://updates.cdn-apple.com/restore.ipsw")
        self.assertEqual(cache["extracted_payloads"], ["ibec", "ibss"])


if __name__ == "__main__":
    unittest.main()
