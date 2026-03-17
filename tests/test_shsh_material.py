import shutil
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

from odtslib.device_state import DeviceStateReport, ToolProbe
from odtslib.exceptions import ODTSError
from odtslib.shsh_material import acquire_shsh_for_connected_device


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


class _FakeTSSChecker:
    def __init__(self, content: bytes):
        self.content = content

    def inspect(self):
        return type(
            "ToolValidation",
            (),
            {
                "runnable": True,
                "path": "/opt/homebrew/bin/tsschecker",
                "selected_candidate": "system",
                "detail": "ok",
            },
        )()

    def request_shsh(self, *, cwd, **_kwargs):
        path = Path(_kwargs["save_path"]) / "ticket.shsh2"
        path.write_bytes(self.content)
        return type("CommandResult", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()

    def build_request_shsh_command(self, **kwargs):
        parts = ["tsschecker", "-d", kwargs["device_model"], "-e", kwargs["ecid"], "--buildid", kwargs["build_id"]]
        if kwargs.get("board_config"):
            parts.extend(["-B", kwargs["board_config"]])
        if kwargs.get("build_manifest"):
            parts.extend(["-m", kwargs["build_manifest"]])
        if kwargs.get("save_path"):
            parts.extend(["--save-path", str(kwargs["save_path"])])
        parts.append("-s")
        return " ".join(parts)


class _FailingTSSChecker(_FakeTSSChecker):
    def request_shsh(self, *, cwd, **_kwargs):
        (Path(cwd) / "tsschecker.log").write_text("opened manifest\n", encoding="utf-8")
        raise ODTSError("Command failed with exit code 1: tsschecker\nfailed to build TSS request")


class _FakeRegistry:
    def __init__(self, content: bytes):
        self.tsschecker = _FakeTSSChecker(content)


class _FailingRegistry:
    def __init__(self):
        self.tsschecker = _FailingTSSChecker(b"")


class _FallbackBuildContext:
    def __call__(self, product, *, build_override, latest_signed):
        if latest_signed:
            return {
                "build": "23P3120",
                "version": "10.3",
                "source": "latest signed build for connected device context",
                "manifest_path": None,
            }
        return {
            "build": "19P647",
            "version": "6.1",
            "source": "repo-aligned default manifest",
            "manifest_path": "/tmp/BuildManifest.plist",
        }


class SHSHMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="odts-shsh-test-"))
        self.output_path = self.temp_dir / "resources" / "shsh.shsh"
        self.metadata_path = self.temp_dir / "resources" / "shsh.metadata.json"
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_acquire_shsh_writes_normalized_output(self):
        with patch("odtslib.shsh_material.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.shsh_material._build_context", return_value={"build": "19P647", "version": "6.1", "source": "repo-aligned default manifest", "manifest_path": None}):
                with patch("odtslib.shsh_material.ToolRegistry", return_value=_FakeRegistry(b"ticket-data")):
                    with patch("odtslib.shsh_material.SHSH_PATH", self.output_path):
                        with patch("odtslib.shsh_material.SHSH_METADATA_PATH", self.metadata_path):
                            with patch("odtslib.shsh_material._host_side_compatibility_probe", return_value={"manifest_build": "19P647", "im4m_generation_succeeded": True, "available_artifacts_wrapped_successfully": 2, "available_artifacts_rejected": 0, "host_side_mismatch_rejected": False}):
                                report = acquire_shsh_for_connected_device()
        self.assertTrue(self.output_path.exists())
        self.assertEqual(self.output_path.read_bytes(), b"ticket-data")
        self.assertEqual(report["write_status"], "newly_created")
        self.assertEqual(report["selected_build"], "19P647")
        self.assertEqual(report["build_source"], "repo-aligned default manifest")
        self.assertFalse(report["host_compatibility"]["host_side_mismatch_rejected"])
        metadata = json.loads(self.metadata_path.read_text(encoding="utf-8"))
        self.assertEqual(metadata["used_build"], "19P647")
        self.assertFalse(metadata["fallback_used"])

    def test_acquire_shsh_reuses_existing_when_bytes_match(self):
        self.output_path.write_bytes(b"ticket-data")
        with patch("odtslib.shsh_material.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.shsh_material._build_context", return_value={"build": "19P647", "version": "6.1", "source": "explicit --build override", "manifest_path": None}):
                with patch("odtslib.shsh_material.ToolRegistry", return_value=_FakeRegistry(b"ticket-data")):
                    with patch("odtslib.shsh_material.SHSH_PATH", self.output_path):
                        with patch("odtslib.shsh_material.SHSH_METADATA_PATH", self.metadata_path):
                            with patch("odtslib.shsh_material._host_side_compatibility_probe", return_value={"manifest_build": "19P647", "im4m_generation_succeeded": True, "available_artifacts_wrapped_successfully": 2, "available_artifacts_rejected": 0, "host_side_mismatch_rejected": False}):
                                report = acquire_shsh_for_connected_device(build="19P647")
        self.assertEqual(report["write_status"], "reused_existing")
        self.assertEqual(self.output_path.read_bytes(), b"ticket-data")

    def test_acquire_shsh_reports_failure_diagnostics(self):
        with patch("odtslib.shsh_material.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.shsh_material._build_context", return_value={"build": "19P647", "version": "6.1", "source": "repo-aligned default manifest", "manifest_path": "/tmp/BuildManifest.plist"}):
                with patch("odtslib.shsh_material.ToolRegistry", return_value=_FailingRegistry()):
                    with patch("odtslib.shsh_material.SHSH_PATH", self.output_path):
                        with patch("odtslib.shsh_material.SHSH_METADATA_PATH", self.metadata_path):
                            report = acquire_shsh_for_connected_device(build="19P647")
        self.assertFalse(report["acquired"])
        self.assertEqual(report["write_status"], "not_written")
        self.assertIn("-B j152fap", report["command"])
        self.assertIn("--buildid 19P647", report["command"])
        self.assertIn("--save-path", report["command"])
        self.assertIn("-m /tmp/BuildManifest.plist", report["command"])
        self.assertTrue(report["manifest_supplied_explicitly"])
        self.assertTrue(any(path.endswith("tsschecker.log") for path in report["temp_files"]))

    def test_acquire_shsh_falls_back_to_latest_signed_after_repo_aligned_failure(self):
        with patch("odtslib.shsh_material.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.shsh_material._build_context", side_effect=_FallbackBuildContext()):
                with patch("odtslib.shsh_material._latest_signed_build_context", return_value={"build": "23P3120", "version": "10.3", "source": "latest signed build for connected device context", "manifest_path": None}):
                    with patch("odtslib.shsh_material.SHSH_PATH", self.output_path):
                        with patch("odtslib.shsh_material.SHSH_METADATA_PATH", self.metadata_path):
                            with patch("odtslib.shsh_material._host_side_compatibility_probe", return_value={"manifest_build": "19P647", "im4m_generation_succeeded": True, "available_artifacts_wrapped_successfully": 2, "available_artifacts_rejected": 0, "host_side_mismatch_rejected": False}):
                                with patch("odtslib.shsh_material.ToolRegistry", side_effect=[_FailingRegistry(), _FakeRegistry(b"ticket-data")]):
                                    report = acquire_shsh_for_connected_device()
        self.assertTrue(report["acquired"])
        self.assertTrue(report["fallback_used"])
        self.assertFalse(report["requested_latest_signed"])
        self.assertTrue(report["used_latest_signed"])
        self.assertEqual(report["acquisition_strategy"], "repo-aligned then latest signed")
        self.assertEqual(report["used_build"], "23P3120")
        self.assertEqual(len(report["attempted_builds"]), 2)
        self.assertEqual(report["attempted_builds"][0]["build"], "19P647")
        self.assertFalse(report["attempted_builds"][0]["acquired"])
        self.assertEqual(report["attempted_builds"][1]["build"], "23P3120")
        self.assertTrue(report["attempted_builds"][1]["acquired"])

    def test_acquire_shsh_latest_signed_marks_requested_mode(self):
        with patch("odtslib.shsh_material.collect_device_state_report", return_value=_device_report()):
            with patch("odtslib.shsh_material._build_context", return_value={"build": "23P3120", "version": "9.3", "source": "latest signed build for connected device context", "manifest_path": None}):
                with patch("odtslib.shsh_material.ToolRegistry", return_value=_FakeRegistry(b"ticket-data")):
                    with patch("odtslib.shsh_material.SHSH_PATH", self.output_path):
                        with patch("odtslib.shsh_material.SHSH_METADATA_PATH", self.metadata_path):
                            with patch("odtslib.shsh_material._host_side_compatibility_probe", return_value={"manifest_build": "19P647", "im4m_generation_succeeded": True, "available_artifacts_wrapped_successfully": 1, "available_artifacts_rejected": 1, "host_side_mismatch_rejected": True}):
                                report = acquire_shsh_for_connected_device(latest_signed=True)
        self.assertTrue(report["requested_latest_signed"])
        self.assertTrue(report["used_latest_signed"])
        self.assertEqual(report["selected_build"], "23P3120")
        self.assertEqual(report["build_source"], "latest signed build for connected device context")
        self.assertTrue(report["host_compatibility"]["host_side_mismatch_rejected"])


if __name__ == "__main__":
    unittest.main()
