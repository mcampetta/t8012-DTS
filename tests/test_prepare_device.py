import io
import logging
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import odts
from odtslib.device_state import DeviceStateReport, ToolProbe


def _device_report(state: str = "identifiers_ready") -> DeviceStateReport:
    return DeviceStateReport(
        state=state,
        meaning="ok",
        evidence=["connected"],
        identifiers={
            "ECID": "0x1234" if state == "identifiers_ready" else None,
            "BDID": "0x3a" if state == "identifiers_ready" else None,
            "CPID": "0x8012" if state == "identifiers_ready" else None,
            "PRODUCT": "iBridge2,14" if state == "identifiers_ready" else None,
            "MODEL": "j152fap" if state == "identifiers_ready" else None,
            "MODE": "Recovery" if state == "identifiers_ready" else None,
        },
        tools=[
            ToolProbe(
                tool="irecovery",
                path="/opt/homebrew/bin/irecovery",
                success=state == "identifiers_ready",
                stdout="",
                stderr="",
                returncode=0 if state == "identifiers_ready" else 1,
                detail="query succeeded",
                selected_candidate="system",
                candidates=[],
            )
        ],
        likely_next_step="next",
        likely_failure_causes=["none"],
        compatible_with_later_stages=state == "identifiers_ready",
    )


class PrepareDeviceTests(unittest.TestCase):
    def test_prepare_device_reports_missing_connected_device(self):
        args = Namespace(
            json=False,
            build=None,
            ipsw=None,
            payload_root=None,
        )
        with patch("odts.collect_device_state_report", return_value=_device_report("no_device")):
            output = io.StringIO()
            with redirect_stdout(output):
                status = odts.run_prepare_device(args, logging.getLogger("test"))
        self.assertEqual(status, 2)
        rendered = output.getvalue()
        self.assertIn("Device detected: False", rendered)
        self.assertIn("Next recommended command: ./venv/bin/python odts.py --device-state --verbose", rendered)

    def test_prepare_device_uses_remote_helper_and_runs_preflight(self):
        args = Namespace(
            json=False,
            build=None,
            ipsw=None,
            payload_root=None,
        )
        payload_report = {
            "build": "19P647",
            "remote_url": "https://example.test/restore.ipsw",
            "manifest_destination": str(Path("/tmp/IPSW/BuildManifest.plist")),
            "actions": [{"component": "BuildManifest", "status": "extracted", "destination_path": "/tmp/IPSW/BuildManifest.plist"}],
            "all_planned_payloads_available_remotely": True,
            "fallback": None,
        }
        preflight = {
            "blockers": ["signing material missing: resources/shsh.shsh is not present"],
            "readiness": {"level": "ready for planning only"},
        }
        with patch("odts.collect_device_state_report", return_value=_device_report()):
            with patch("odts._default_repo_build", return_value="19P647"):
                with patch("odts.inspect_remote_payload_layout", return_value=payload_report) as inspect_remote:
                    with patch("odts.load_manifest_for_planning", return_value=object()):
                        with patch("odts.build_execution_preflight", return_value=preflight):
                            output = io.StringIO()
                            with redirect_stdout(output):
                                status = odts.run_prepare_device(args, logging.getLogger("test"))
        self.assertEqual(status, 0)
        inspect_remote.assert_called_once()
        self.assertEqual(inspect_remote.call_args.kwargs["device"], "iBridge2,14")
        self.assertEqual(inspect_remote.call_args.kwargs["board_config"], "j152fap")
        self.assertEqual(inspect_remote.call_args.kwargs["build"], "19P647")
        rendered = output.getvalue()
        self.assertIn("Build source: repo-aligned default manifest", rendered)
        self.assertIn("Payload source used: remote_ipsw", rendered)
        self.assertIn("Current readiness level: ready for planning only", rendered)
        self.assertIn("Next recommended command: ./venv/bin/python odts.py --acquire-shsh", rendered)

    def test_prepare_device_json_includes_explicit_build_source(self):
        args = Namespace(
            json=True,
            build="19P647",
            ipsw=None,
            payload_root=None,
        )
        payload_report = {
            "build": "19P647",
            "remote_url": "https://example.test/restore.ipsw",
            "manifest_destination": str(Path("/tmp/IPSW/BuildManifest.plist")),
            "actions": [],
            "all_planned_payloads_available_remotely": True,
            "fallback": None,
        }
        preflight = {
            "blockers": [],
            "readiness": {"level": "ready for planning only"},
        }
        with patch("odts.collect_device_state_report", return_value=_device_report()):
            with patch("odts._default_repo_build", return_value="19P999"):
                with patch("odts.inspect_remote_payload_layout", return_value=payload_report):
                    with patch("odts.load_manifest_for_planning", return_value=object()):
                        with patch("odts.build_execution_preflight", return_value=preflight):
                            output = io.StringIO()
                            with redirect_stdout(output):
                                status = odts.run_prepare_device(args, logging.getLogger("test"))
        self.assertEqual(status, 0)
        self.assertIn('"selected_build": "19P647"', output.getvalue())
        self.assertIn('"build_source": "explicit --build override"', output.getvalue())


if __name__ == "__main__":
    unittest.main()
