import unittest
import uuid
from pathlib import Path

from odtslib.device import parse_irecovery_query, read_board_config

TEST_TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


class DeviceHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TEST_TMP_ROOT / f"device-{uuid.uuid4().hex}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.temp_dir.exists():
            for path in sorted(self.temp_dir.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            self.temp_dir.rmdir()

    def test_parse_irecovery_query_extracts_key_values(self):
        parsed = parse_irecovery_query("ECID: 0x1234\nBDID: 0x0A\nMODEL: iBridge2,5\n")
        self.assertEqual(parsed["ECID"], "0x1234")
        self.assertEqual(parsed["BDID"], "0x0A")
        self.assertEqual(parsed["MODEL"], "iBridge2,5")

    def test_read_board_config_finds_matching_ap_value(self):
        mapping = self.temp_dir / "device_map.txt"
        mapping.write_text("CPID:8012 SCEP:00 BDID:0A SDOM:01 t8012 j137ap\n", encoding="utf-8")
        self.assertEqual(read_board_config("0A", mapping), "j137ap")


if __name__ == "__main__":
    unittest.main()
