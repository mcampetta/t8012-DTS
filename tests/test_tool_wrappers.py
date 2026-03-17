import stat
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from odtslib.exceptions import ExternalToolError
from odtslib.subprocess_utils import CommandResult
from odtslib.tool_wrappers import ExternalBinaryWrapper, Img4Tool, ToolCandidate

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

    def make_executable(self, path: Path, content: str = "#!/bin/sh\nexit 0\n") -> Path:
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return path

    def test_missing_binary_raises_structured_error(self):
        wrapper = ExternalBinaryWrapper(
            "missing-tool",
            self.temp_dir / "missing-tool",
            candidates=[ToolCandidate("bundled", self.temp_dir / "missing-tool")],
        )
        with self.assertRaises(ExternalToolError):
            wrapper.validate_exists()

    def test_version_detection_reads_output(self):
        script = self.temp_dir / "tool.py"
        script.write_text("import sys\nprint('img4tool 1.2.3')\n", encoding="utf-8")
        wrapper = ExternalBinaryWrapper(
            "python-tool",
            Path(sys.executable),
            candidates=[ToolCandidate("system", Path(sys.executable))],
            version_commands=[[script]],
            version_pattern=r"img4tool\s+\d+\.\d+\.\d+",
        )
        self.assertEqual(wrapper.detect_version(), "img4tool 1.2.3")

    def test_img4tool_dry_run_exposes_python_interface(self):
        binary = self.make_executable(self.temp_dir / "img4tool")
        wrapper = Img4Tool()
        wrapper.candidates = [ToolCandidate("bundled", binary)]
        result = wrapper.sign_img4(
            output_path="out.img4",
            payload_path="payload.im4p",
            shsh_path="ticket.shsh",
            image_type="ibss",
            dry_run=True,
        )
        self.assertTrue(result.skipped)
        self.assertEqual(result.args[1:], ["-c", "out.img4", "-t", "ibss", "-p", "payload.im4p", "-s", "ticket.shsh"])

    def test_loader_failure_is_classified_and_rejected(self):
        binary = self.make_executable(self.temp_dir / "irecovery")
        wrapper = ExternalBinaryWrapper(
            "irecovery",
            binary,
            candidates=[ToolCandidate("bundled", binary)],
            version_commands=[["-h"]],
        )

        with patch(
            "odtslib.tool_wrappers.run_command",
            return_value=CommandResult(
                args=[str(binary), "-h"],
                returncode=1,
                stdout="",
                stderr="dyld: Library not loaded: /usr/local/lib/libirecovery.3.dylib",
            ),
        ):
            inspection = wrapper.inspect()

        self.assertFalse(inspection.runnable)
        self.assertEqual(inspection.candidates[0].status, "loader_failure")
        self.assertIn("Library not loaded", inspection.candidates[0].detail)

    def test_candidate_fallback_prefers_runnable_system_binary_over_bundled_loader_failure(self):
        system_binary = self.make_executable(self.temp_dir / "irecovery-system")
        bundled_binary = self.make_executable(self.temp_dir / "irecovery-bundled")
        wrapper = ExternalBinaryWrapper(
            "irecovery",
            bundled_binary,
            candidates=[
                ToolCandidate("system", system_binary),
                ToolCandidate("bundled", bundled_binary),
            ],
            version_commands=[["-h"]],
            version_pattern=r"irecovery[^\r\n]*",
        )

        def fake_run(args, **kwargs):
            target = str(args[0])
            if target == str(system_binary):
                return CommandResult(args=[target, "-h"], returncode=0, stdout="irecovery 1.0.0\n", stderr="")
            return CommandResult(
                args=[target, "-h"],
                returncode=1,
                stdout="",
                stderr="dyld: Library not loaded: /usr/local/lib/libirecovery.3.dylib",
            )

        with patch("odtslib.tool_wrappers.run_command", side_effect=fake_run):
            inspection = wrapper.inspect()
            selected = wrapper.validate_exists()

        self.assertTrue(inspection.runnable)
        self.assertEqual(inspection.path, str(system_binary))
        self.assertEqual(inspection.selected_candidate, "system")
        self.assertEqual(selected, system_binary)
        self.assertEqual(inspection.candidates[0].status, "runnable")
        self.assertEqual(inspection.candidates[1].status, "loader_failure")

    def test_non_executable_candidate_is_reported(self):
        binary = self.temp_dir / "patcher"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        wrapper = ExternalBinaryWrapper(
            "patcher",
            binary,
            candidates=[ToolCandidate("bundled", binary)],
            version_commands=[["-h"]],
        )

        inspection = wrapper.inspect()

        self.assertFalse(inspection.runnable)
        self.assertEqual(inspection.candidates[0].status, "not_executable")

    def test_nonzero_usage_probe_can_still_be_accepted_as_runnable(self):
        binary = self.make_executable(self.temp_dir / "patcher")
        wrapper = ExternalBinaryWrapper(
            "patcher",
            binary,
            candidates=[ToolCandidate("bundled", binary)],
            version_commands=[["-h"]],
        )

        with patch(
            "odtslib.tool_wrappers.run_command",
            return_value=CommandResult(
                args=[str(binary), "-h"],
                returncode=255,
                stdout="",
                stderr="Usage: patcher <input> <output>",
            ),
        ):
            inspection = wrapper.inspect()

        self.assertTrue(inspection.runnable)
        self.assertEqual(inspection.candidates[0].status, "runnable")
        self.assertIn("usable help/version output", inspection.candidates[0].detail)


if __name__ == "__main__":
    unittest.main()
