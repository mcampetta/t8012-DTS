from __future__ import annotations

import os
import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .config import BIN_DIR, PROJECT_ROOT
from .exceptions import DependencyError, ExternalToolError, ODTSError
from .subprocess_utils import CommandResult, format_command, run_command


@dataclass(frozen=True)
class ToolCandidate:
    label: str
    reference: str | Path


@dataclass
class CandidateValidation:
    label: str
    reference: str
    path: str | None
    status: str
    detail: str
    returncode: int | None
    version: str | None
    selected: bool = False


@dataclass
class ToolValidation:
    name: str
    path: str | None
    exists: bool
    version: str | None
    runnable: bool
    detail: str
    selected_candidate: str | None
    candidates: list[CandidateValidation]


class ExternalBinaryWrapper:
    def __init__(
        self,
        name: str,
        path: str | Path,
        *,
        candidates: Iterable[str | Path | ToolCandidate] | None = None,
        version_commands: Iterable[Sequence[str | Path]] | None = None,
        version_pattern: str | None = None,
    ) -> None:
        self.name = name
        self.path = Path(path)
        self.candidates = list(candidates or [ToolCandidate("system", name), ToolCandidate("bundled", path)])
        self.version_commands = [list(command) for command in (version_commands or [])]
        self.version_pattern = re.compile(version_pattern, re.IGNORECASE) if version_pattern else None

    @staticmethod
    def _runtime_failure_detail(text: str) -> str | None:
        trimmed = text.strip()
        lowered = trimmed.lower()
        failure_markers = (
            "library not loaded",
            "image not found",
            "not in dyld cache",
            "bad cpu type",
            "cannot execute",
            "exec format error",
            "killed:",
            "trace/breakpoint trap",
            "segmentation fault",
            "permission denied",
        )
        if any(marker in lowered for marker in failure_markers):
            return trimmed[:200] or "runtime loader failure"
        return None

    def _iter_candidates(self) -> list[ToolCandidate]:
        normalized: list[ToolCandidate] = []
        seen: set[tuple[str, str]] = set()
        for entry in self.candidates:
            if isinstance(entry, ToolCandidate):
                candidate = entry
            else:
                label = "system" if isinstance(entry, str) and Path(entry).name == entry else "bundled"
                candidate = ToolCandidate(label, entry)
            key = (candidate.label, str(candidate.reference))
            if key in seen:
                continue
            seen.add(key)
            normalized.append(candidate)
        return normalized

    def _resolve_candidate_path(self, candidate: ToolCandidate) -> Path | None:
        if isinstance(candidate.reference, str):
            reference = Path(candidate.reference)
            if len(reference.parts) == 1:
                found = shutil.which(candidate.reference)
                return Path(found) if found else None
            return reference if reference.is_absolute() else PROJECT_ROOT / reference
        return candidate.reference if candidate.reference.is_absolute() else PROJECT_ROOT / candidate.reference

    def _extract_version(self, text: str) -> str | None:
        trimmed = text.strip()
        if not trimmed:
            return None
        if self.version_pattern:
            match = self.version_pattern.search(trimmed)
            if match:
                return match.group(0)
        return trimmed.splitlines()[0][:200]

    def _probe_output_is_acceptable(self, text: str) -> bool:
        trimmed = text.strip()
        if not trimmed:
            return False
        if self.version_pattern and self.version_pattern.search(trimmed):
            return True
        lowered = trimmed.lower()
        markers = ("usage:", "usage ", "options:", "help", "version", self.name.lower())
        return any(marker in lowered for marker in markers)

    def _probe_candidate(self, candidate: ToolCandidate, *, dry_run: bool = False) -> CandidateValidation:
        resolved = self._resolve_candidate_path(candidate)
        if resolved is None:
            return CandidateValidation(
                label=candidate.label,
                reference=str(candidate.reference),
                path=None,
                status="missing_binary",
                detail="candidate not found on PATH",
                returncode=None,
                version=None,
            )
        if not resolved.exists():
            return CandidateValidation(
                label=candidate.label,
                reference=str(candidate.reference),
                path=str(resolved),
                status="missing_binary",
                detail="candidate path does not exist",
                returncode=None,
                version=None,
            )
        if not resolved.is_file():
            return CandidateValidation(
                label=candidate.label,
                reference=str(candidate.reference),
                path=str(resolved),
                status="missing_binary",
                detail="candidate path is not a file",
                returncode=None,
                version=None,
            )
        if not os.access(resolved, os.X_OK):
            return CandidateValidation(
                label=candidate.label,
                reference=str(candidate.reference),
                path=str(resolved),
                status="not_executable",
                detail="candidate exists but is not executable",
                returncode=None,
                version=None,
            )
        if dry_run:
            return CandidateValidation(
                label=candidate.label,
                reference=str(candidate.reference),
                path=str(resolved),
                status="runnable",
                detail="dry-run probe skipped",
                returncode=0,
                version="dry-run",
            )

        commands = self.version_commands or [["-h"]]
        last_bad_exit: CandidateValidation | None = None
        for command in commands:
            try:
                result = run_command([resolved, *command], check=False, dry_run=False)
            except DependencyError as exc:
                return CandidateValidation(
                    label=candidate.label,
                    reference=str(candidate.reference),
                    path=str(resolved),
                    status="missing_binary",
                    detail=str(exc),
                    returncode=None,
                    version=None,
                )
            except ODTSError as exc:
                detail = str(exc)
                runtime_failure = self._runtime_failure_detail(detail)
                return CandidateValidation(
                    label=candidate.label,
                    reference=str(candidate.reference),
                    path=str(resolved),
                    status="loader_failure" if runtime_failure else "bad_exit_code",
                    detail=(runtime_failure or detail)[:200],
                    returncode=None,
                    version=None,
                )

            output_text = "\n".join(part for part in [result.stderr.strip(), result.stdout.strip()] if part).strip()
            runtime_failure = self._runtime_failure_detail(output_text)
            if runtime_failure:
                return CandidateValidation(
                    label=candidate.label,
                    reference=str(candidate.reference),
                    path=str(resolved),
                    status="loader_failure",
                    detail=runtime_failure,
                    returncode=result.returncode,
                    version=None,
                )

            version = self._extract_version(output_text)
            if result.returncode == 0:
                return CandidateValidation(
                    label=candidate.label,
                    reference=str(candidate.reference),
                    path=str(resolved),
                    status="runnable",
                    detail="probe succeeded",
                    returncode=result.returncode,
                    version=version,
                )
            if self._probe_output_is_acceptable(output_text):
                return CandidateValidation(
                    label=candidate.label,
                    reference=str(candidate.reference),
                    path=str(resolved),
                    status="runnable",
                    detail=f"probe returned {result.returncode} but produced usable help/version output",
                    returncode=result.returncode,
                    version=version,
                )
            last_bad_exit = CandidateValidation(
                label=candidate.label,
                reference=str(candidate.reference),
                path=str(resolved),
                status="bad_exit_code",
                detail=(output_text or f"probe exited with code {result.returncode}")[:200],
                returncode=result.returncode,
                version=version,
            )

        if last_bad_exit:
            return last_bad_exit
        return CandidateValidation(
            label=candidate.label,
            reference=str(candidate.reference),
            path=str(resolved),
            status="bad_exit_code",
            detail="probe produced no output",
            returncode=None,
            version=None,
        )

    def resolve(self, *, dry_run: bool = False) -> ToolValidation:
        candidates = [self._probe_candidate(candidate, dry_run=dry_run) for candidate in self._iter_candidates()]
        selected = next((candidate for candidate in candidates if candidate.status == "runnable"), None)
        if selected:
            selected.selected = True
            return ToolValidation(
                name=self.name,
                path=selected.path,
                exists=True,
                version=selected.version,
                runnable=True,
                detail=selected.detail,
                selected_candidate=selected.label,
                candidates=candidates,
            )

        first_present = next((candidate for candidate in candidates if candidate.path), None)
        detail = "; ".join(
            f"{candidate.label}: {candidate.status} ({candidate.detail})" for candidate in candidates
        )[:500]
        return ToolValidation(
            name=self.name,
            path=first_present.path if first_present else None,
            exists=bool(first_present),
            version=None,
            runnable=False,
            detail=detail or "no candidates configured",
            selected_candidate=None,
            candidates=candidates,
        )

    def validate_exists(self, *, dry_run: bool = False) -> Path:
        validation = self.resolve(dry_run=dry_run)
        if validation.runnable and validation.path:
            return Path(validation.path)
        raise ExternalToolError(f"No runnable {self.name} binary found. {validation.detail}")

    def detect_version(self, *, dry_run: bool = False) -> str | None:
        validation = self.resolve(dry_run=dry_run)
        if validation.runnable:
            return validation.version
        raise ExternalToolError(f"No runnable {self.name} binary found. {validation.detail}")

    def inspect(self, *, dry_run: bool = False) -> ToolValidation:
        return self.resolve(dry_run=dry_run)

    def run(
        self,
        args: Sequence[str | Path],
        *,
        check: bool = True,
        dry_run: bool = False,
        cwd: str | Path | None = None,
    ) -> CommandResult:
        try:
            return run_command(args, check=check, dry_run=dry_run, cwd=cwd)
        except Exception as exc:
            raise ExternalToolError(f"{self.name} failed: {exc}") from exc


class IRecoveryTool(ExternalBinaryWrapper):
    def __init__(self) -> None:
        super().__init__(
            "irecovery",
            BIN_DIR / "irecovery",
            version_commands=[["-h"]],
            version_pattern=r"libirecovery[^\r\n]*|irecovery[^\r\n]*",
        )

    def query(self, *, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, "-q"], dry_run=dry_run)

    def send_file(self, image_path: str | Path, *, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, "-f", image_path], dry_run=dry_run)

    def send_command(self, command: str, *, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, "-c", command], dry_run=dry_run)


class TSSCheckerTool(ExternalBinaryWrapper):
    def __init__(self) -> None:
        super().__init__(
            "tsschecker",
            BIN_DIR / "tsschecker",
            version_commands=[["-h"]],
            version_pattern=r"tsschecker[^\r\n]*|version[^\r\n]*",
        )

    def request_shsh(
        self,
        *,
        device_model: str,
        ecid: str,
        ios_version: str,
        board_config: str | None = None,
        build_id: str | None = None,
        build_manifest: str | Path | None = None,
        save_path: str | Path | None = None,
        update_install: bool = False,
        cwd: str | Path | None = None,
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        args: list[str | Path] = [binary, "-d", device_model, "-e", ecid]
        if build_id:
            args.extend(["--buildid", build_id])
        else:
            args.extend(["-i", ios_version])
        if board_config:
            args.extend(["-B", board_config])
        if build_manifest:
            args.extend(["-m", build_manifest])
        if save_path:
            save_dir = Path(save_path)
            save_dir.mkdir(parents=True, exist_ok=True)
            args.extend(["--save-path", save_dir])
        if update_install:
            args.append("-u")
        args.append("-s")
        return self.run(args, dry_run=dry_run, cwd=cwd)

    def build_request_shsh_command(
        self,
        *,
        device_model: str,
        ecid: str,
        ios_version: str,
        board_config: str | None = None,
        build_id: str | None = None,
        build_manifest: str | Path | None = None,
        save_path: str | Path | None = None,
        update_install: bool = False,
        dry_run: bool = False,
    ) -> str:
        binary = self.validate_exists(dry_run=dry_run)
        args: list[str | Path] = [binary, "-d", device_model, "-e", ecid]
        if build_id:
            args.extend(["--buildid", build_id])
        else:
            args.extend(["-i", ios_version])
        if board_config:
            args.extend(["-B", board_config])
        if build_manifest:
            args.extend(["-m", build_manifest])
        if save_path:
            args.extend(["--save-path", save_path])
        if update_install:
            args.append("-u")
        args.append("-s")
        return format_command(args)


class Img4Tool(ExternalBinaryWrapper):
    def __init__(self) -> None:
        super().__init__(
            "img4tool",
            BIN_DIR / "img4tool",
            version_commands=[["-h"]],
            version_pattern=r"img4tool[^\r\n]*|version[^\r\n]*",
        )

    def extract_kbag(self, image_path: str | Path, *, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, "-a", image_path], dry_run=dry_run)

    def decrypt_im4p(
        self,
        *,
        image_path: str | Path,
        output_path: str | Path,
        iv: str,
        key: str,
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run(
            [binary, "-e", "-o", output_path, "--iv", iv, "--key", key, image_path],
            dry_run=dry_run,
        )

    def extract_im4m(
        self,
        *,
        shsh_path: str | Path,
        output_path: str | Path,
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, "-e", "-s", shsh_path, "-m", output_path], dry_run=dry_run)

    def create_im4p(
        self,
        *,
        output_path: str | Path,
        image_type: str,
        payload_path: str | Path,
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, "-c", output_path, "-t", image_type, payload_path], dry_run=dry_run)

    def sign_img4(
        self,
        *,
        output_path: str | Path,
        payload_path: str | Path,
        shsh_path: str | Path | None = None,
        manifest_path: str | Path | None = None,
        image_type: str | None = None,
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        args: list[str | Path] = [binary, "-c", output_path]
        if image_type:
            args.extend(["-t", image_type])
        if payload_path:
            args.extend(["-p", payload_path] if shsh_path or manifest_path else [payload_path])
        if shsh_path:
            args.extend(["-s", shsh_path])
        if manifest_path:
            args.extend(["-m", manifest_path])
        return self.run(args, dry_run=dry_run)


class Img4Binary(ExternalBinaryWrapper):
    def __init__(self) -> None:
        super().__init__(
            "img4",
            BIN_DIR / "img4",
            version_commands=[["-h"]],
            version_pattern=r"img4[^\r\n]*|usage[^\r\n]*",
        )

    def unpack(self, *, input_path: str | Path, output_path: str | Path, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, "-i", input_path, "-o", output_path], dry_run=dry_run)


class IBootIMTool(ExternalBinaryWrapper):
    def __init__(self) -> None:
        super().__init__(
            "ibootim",
            BIN_DIR / "ibootim",
            version_commands=[["-h"]],
            version_pattern=r"ibootim[^\r\n]*|usage[^\r\n]*",
        )

    def convert_png(self, *, input_path: str | Path, output_path: str | Path, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, input_path, output_path], dry_run=dry_run)


class BinaryPatcherTool(ExternalBinaryWrapper):
    def __init__(self, binary_name: str) -> None:
        super().__init__(
            binary_name,
            BIN_DIR / binary_name,
            version_commands=[["-h"]],
            version_pattern=rf"{re.escape(binary_name)}[^\r\n]*|usage[^\r\n]*",
        )

    def patch_iboot(
        self,
        *,
        input_path: str | Path,
        output_path: str | Path,
        boot_args: str | None = None,
        extra_args: Sequence[str | Path] | None = None,
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        args: list[str | Path] = [binary, input_path, output_path]
        if boot_args:
            args.extend(["-b", boot_args])
        if extra_args:
            args.extend(extra_args)
        return self.run(args, dry_run=dry_run)


class GenericBinaryTool(ExternalBinaryWrapper):
    def __init__(
        self,
        name: str,
        path: str | Path,
        *,
        version_commands: Iterable[Sequence[str | Path]] | None = None,
        version_pattern: str | None = None,
    ) -> None:
        super().__init__(name, path, version_commands=version_commands, version_pattern=version_pattern)

    def execute(self, *args: str | Path, dry_run: bool = False, cwd: str | Path | None = None) -> CommandResult:
        binary = self.validate_exists(dry_run=dry_run)
        return self.run([binary, *args], dry_run=dry_run, cwd=cwd)


class ToolRegistry:
    def __init__(self) -> None:
        self.irecovery = IRecoveryTool()
        self.tsschecker = TSSCheckerTool()
        self.img4tool = Img4Tool()
        self.img4 = Img4Binary()
        self.ibootim = IBootIMTool()
        self.iboot64patcher = BinaryPatcherTool("iBoot64Patcher")
        self.kernel64patcher = BinaryPatcherTool("Kernel64Patcher")
        self.dtree_patcher = BinaryPatcherTool("dtree_patcher")
        self.kairos = BinaryPatcherTool("kairos")
        self.ipwnder32 = GenericBinaryTool("iPwnder32", BIN_DIR / "iPwnder32", version_commands=[["-h"]])
        self.eclipsa8000 = GenericBinaryTool("eclipsa8000", BIN_DIR / "eclipsa8000", version_commands=[["-h"]])
        self.eclipsa8003 = GenericBinaryTool("eclipsa8003", BIN_DIR / "eclipsa8003", version_commands=[["-h"]])
        self.eclipsa7000 = GenericBinaryTool("eclipsa7000", BIN_DIR / "eclipsa7000", version_commands=[["-h"]])
        self.eclipsa7001 = GenericBinaryTool("eclipsa7001", BIN_DIR / "eclipsa7001", version_commands=[["-h"]])

    def inspect(self, *, dry_run: bool = False) -> list[dict[str, object]]:
        tools = [
            self.irecovery,
            self.tsschecker,
            self.img4tool,
            self.img4,
            self.ibootim,
            self.iboot64patcher,
            self.kernel64patcher,
            self.dtree_patcher,
            self.kairos,
            self.ipwnder32,
            self.eclipsa8000,
            self.eclipsa8003,
            self.eclipsa7000,
            self.eclipsa7001,
        ]
        return [asdict(tool.inspect(dry_run=dry_run)) for tool in tools]
