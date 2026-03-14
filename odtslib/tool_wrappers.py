from __future__ import annotations

import re
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .config import BIN_DIR, PROJECT_ROOT
from .exceptions import ExternalToolError
from .subprocess_utils import CommandResult, run_command


@dataclass
class ToolValidation:
    name: str
    path: str
    exists: bool
    version: str | None
    runnable: bool
    detail: str


class ExternalBinaryWrapper:
    def __init__(
        self,
        name: str,
        path: str | Path,
        *,
        version_commands: Iterable[Sequence[str | Path]] | None = None,
        version_pattern: str | None = None,
    ) -> None:
        self.name = name
        self.path = Path(path)
        self.version_commands = [list(command) for command in (version_commands or [])]
        self.version_pattern = re.compile(version_pattern, re.IGNORECASE) if version_pattern else None

    def _absolute_path(self) -> Path:
        if self.path.is_absolute():
            return self.path
        if len(self.path.parts) == 1:
            found = shutil.which(str(self.path))
            if found:
                return Path(found)
        return PROJECT_ROOT / self.path

    def validate_exists(self) -> Path:
        path = self._absolute_path()
        if not path.exists():
            raise ExternalToolError(
                f"{self.name} is missing at {path}. Restore or install the binary before continuing."
            )
        return path

    def detect_version(self, *, dry_run: bool = False) -> str | None:
        path = self.validate_exists()
        if dry_run:
            return "dry-run"
        for command in self.version_commands:
            result = self.run([path, *command], check=False)
            text = "\n".join(part for part in [result.stdout.strip(), result.stderr.strip()] if part).strip()
            if not text:
                continue
            if self.version_pattern:
                match = self.version_pattern.search(text)
                if match:
                    return match.group(0)
            return text.splitlines()[0][:200]
        return None

    def inspect(self, *, dry_run: bool = False) -> ToolValidation:
        path = self._absolute_path()
        if not path.exists():
            return ToolValidation(
                name=self.name,
                path=str(path),
                exists=False,
                version=None,
                runnable=False,
                detail="missing",
            )
        try:
            version = self.detect_version(dry_run=dry_run)
        except ExternalToolError as exc:
            return ToolValidation(
                name=self.name,
                path=str(path),
                exists=True,
                version=None,
                runnable=False,
                detail=str(exc),
            )
        return ToolValidation(
            name=self.name,
            path=str(path),
            exists=True,
            version=version,
            runnable=True,
            detail="ok",
        )

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
        binary = self.validate_exists()
        return self.run([binary, "-q"], dry_run=dry_run)

    def send_file(self, image_path: str | Path, *, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists()
        return self.run([binary, "-f", image_path], dry_run=dry_run)

    def send_command(self, command: str, *, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists()
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
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists()
        return self.run(
            [binary, "-d", device_model, "-e", ecid, "-i", ios_version, "-s"],
            dry_run=dry_run,
        )


class Img4Tool(ExternalBinaryWrapper):
    def __init__(self) -> None:
        super().__init__(
            "img4tool",
            BIN_DIR / "img4tool",
            version_commands=[["-h"]],
            version_pattern=r"img4tool[^\r\n]*|version[^\r\n]*",
        )

    def extract_kbag(self, image_path: str | Path, *, dry_run: bool = False) -> CommandResult:
        binary = self.validate_exists()
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
        binary = self.validate_exists()
        return self.run(
            [binary, "-e", "-o", output_path, "--iv", iv, "--key", key, image_path],
            dry_run=dry_run,
        )

    def create_im4p(
        self,
        *,
        output_path: str | Path,
        image_type: str,
        payload_path: str | Path,
        dry_run: bool = False,
    ) -> CommandResult:
        binary = self.validate_exists()
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
        binary = self.validate_exists()
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
        binary = self.validate_exists()
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
        binary = self.validate_exists()
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
        binary = self.validate_exists()
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
        binary = self.validate_exists()
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
        self.eclipsa8000 = GenericBinaryTool("eclipsa8000", BIN_DIR / "eclipsa8000")
        self.eclipsa8003 = GenericBinaryTool("eclipsa8003", BIN_DIR / "eclipsa8003")
        self.eclipsa7000 = GenericBinaryTool("eclipsa7000", BIN_DIR / "eclipsa7000")
        self.eclipsa7001 = GenericBinaryTool("eclipsa7001", BIN_DIR / "eclipsa7001")

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
