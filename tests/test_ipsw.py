import plistlib
import unittest
import uuid
from pathlib import Path
from zipfile import ZipFile

from resources import ipsw

TEST_TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


class IPSWTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TEST_TMP_ROOT / f"ipsw-{uuid.uuid4().hex}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if ipsw.LOCAL_IPSW_DIR.exists():
            for path in sorted(ipsw.LOCAL_IPSW_DIR.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            ipsw.LOCAL_IPSW_DIR.rmdir()
        if self.temp_dir.exists():
            for path in sorted(self.temp_dir.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            self.temp_dir.rmdir()

    def test_read_manifest_returns_supported_models(self):
        manifest = self.temp_dir / "BuildManifest.plist"
        manifest.write_bytes(
            plistlib.dumps(
                {"ProductVersion": "6.1", "SupportedProductTypes": ["iBridge2,5", "iBridge2,10"]}
            )
        )
        self.assertEqual(
            ipsw.read_manifest(manifest, return_version=False),
            ["iBridge2,5", "iBridge2,10"],
        )

    def test_unzip_ipsw_extracts_manifest_and_returns_version(self):
        archive_path = self.temp_dir / "fixture.ipsw"
        with ZipFile(archive_path, "w") as archive:
            archive.writestr(
                "BuildManifest.plist",
                plistlib.dumps({"ProductVersion": "6.1", "SupportedProductTypes": ["iBridge2,5"]}),
            )
        self.assertEqual(ipsw.unzip_ipsw(archive_path), "6.1")


if __name__ == "__main__":
    unittest.main()
