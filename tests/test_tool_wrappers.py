import stat
import sys
import unittest
import uuid
from pathlib import Path

from odtslib.exceptions import ExternalToolError
from odtslib.tool_wrappers import ExternalBinaryWrapper, Img4Tool

TEST_TMP_ROOT = Path(__file__).resolve().parent / ".tmp"


class ToolWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TEST_TMP_ROOT / f"tools-{uuid.uuid4().hex}"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self.temp_dir.exists():
            for path in sorted(self.temp_dir.rglob("*"), reverse=True):
                if path.is_file():
                    path.unlink()
                elif path.is_dir():
                    path.rmdir()
            self.temp_dir.rmdir()

    def test_missing_binary_raises_structured_error(self):
        wrapper = ExternalBinaryWrapper("missing-tool", self.temp_dir / "missing-tool")
        with self.assertRaises(ExternalToolError):
            wrapper.validate_exists()

    def test_version_detection_reads_output(self):
        script = self.temp_dir / "tool.py"
        script.write_text("import sys\nprint('img4tool 1.2.3')\n", encoding="utf-8")
        wrapper = ExternalBinaryWrapper(
            "python-tool",
            Path(sys.executable),
            version_commands=[[script]],
            version_pattern=r"img4tool\s+\d+\.\d+\.\d+",
        )
        self.assertEqual(wrapper.detect_version(), "img4tool 1.2.3")

    def test_img4tool_dry_run_exposes_python_interface(self):
        binary = self.temp_dir / "img4tool"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        wrapper = Img4Tool()
        wrapper.path = binary
        result = wrapper.sign_img4(
            output_path="out.img4",
            payload_path="payload.im4p",
            shsh_path="ticket.shsh",
            image_type="ibss",
            dry_run=True,
        )
        self.assertTrue(result.skipped)
        self.assertEqual(result.args[1:], ["-c", "out.img4", "-t", "ibss", "-p", "payload.im4p", "-s", "ticket.shsh"])


if __name__ == "__main__":
    unittest.main()
