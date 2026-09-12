"""herdtools7 的 contract-aware replay 适配器。

herd 的结果只作为 E2.5 的外部 characterization oracle。它不产生
``ProofFact``，也不参与 BMoCheck 的 SAFE/TRACE_SAFE 判定；调用者必须同时
提供 source 输入、contract-lowered target 输入和对应的 DBT contract 绑定。
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .model import HerdOracleRecord, HerdOutcome


class HerdRunStatus(StrEnum):
    """一次 herd 进程的可审计完成状态。"""

    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"
    FAILED = "FAILED"
    UNPARSED = "UNPARSED"


class HerdReplayStatus(StrEnum):
    """记录中的 oracle 与本次 herd 重放的关系。"""

    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class HerdInvocation:
    """一个 source 或 target herd 输入的原始、不可变观察结果。"""

    input_path: str
    model: str
    command: tuple[str, ...]
    status: HerdRunStatus
    outcome: HerdOutcome
    returncode: int | None
    stdout: str
    stderr: str
    input_sha256: str
    raw_output_sha256: str
    reason: str


@dataclass(frozen=True, slots=True)
class HerdOracleRequest:
    """把两份 herd 输入和 DBT lowering contract 绑定在一起。"""

    source_input: Path
    target_input: Path
    source_model: str
    target_model: str
    contract_version: str
    contract_sha256: str
    elf_sha256: str
    herd_executable: str = "herd7"
    timeout_seconds: float = 30.0
    extra_args: tuple[str, ...] = ()
    # 重放时调用者可以显式绑定 herd 版本；None 表示版本由外部运行环境
    # 管理，不能据此宣称记录与当前工具版本相同。
    herd_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.source_input, Path) or not isinstance(self.target_input, Path):
            raise ValueError("herd inputs must be Path values")
        for field in ("source_model", "target_model", "contract_version", "herd_executable"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value or "\x00" in value:
                raise ValueError(f"{field} must be a non-empty string")
        if self.herd_version is not None and (
            not isinstance(self.herd_version, str)
            or not self.herd_version
            or "\x00" in self.herd_version
        ):
            raise ValueError("herd_version must be non-empty when provided")
        for field in ("contract_sha256", "elf_sha256"):
            value = getattr(self, field)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                raise ValueError(f"{field} must be a lowercase SHA-256")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if any("\x00" in argument for argument in self.extra_args):
            raise ValueError("herd arguments cannot contain NUL")


@dataclass(frozen=True, slots=True)
class HerdOracleRun:
    """source/target 两次 herd invocation 的 evaluation-only 结果。"""

    request: HerdOracleRequest
    source: HerdInvocation
    target: HerdInvocation

    @property
    def status(self) -> HerdRunStatus:
        if self.source.status is not HerdRunStatus.COMPLETED:
            return self.source.status
        if self.target.status is not HerdRunStatus.COMPLETED:
            return self.target.status
        return HerdRunStatus.COMPLETED

    @property
    def complete(self) -> bool:
        return (
            self.source.status is HerdRunStatus.COMPLETED
            and self.target.status is HerdRunStatus.COMPLETED
            and self.source.outcome is not HerdOutcome.UNSUPPORTED
            and self.target.outcome is not HerdOutcome.UNSUPPORTED
        )

    @property
    def raw_output_sha256(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.source.stdout.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(self.source.stderr.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(self.target.stdout.encode("utf-8", errors="replace"))
        digest.update(b"\0")
        digest.update(self.target.stderr.encode("utf-8", errors="replace"))
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class HerdReplayResult:
    """已记录 oracle 与新运行结果的 comparison，不是 BMoCheck verdict。"""

    status: HerdReplayStatus
    run: HerdOracleRun
    differences: tuple[str, ...] = ()


_HEADER_RE = re.compile(
    r"^\s*Test\s+.+?\s+(Allowed|Forbidden)\s*$", re.IGNORECASE | re.MULTILINE
)
_CONDITION_RE = re.compile(
    r"\b(?:is\s+)?(not\s+)?confirmed\b", re.IGNORECASE
)


def parse_herd_outcome(output: str) -> HerdOutcome:
    """从 herd 文本提取 outcome；无法唯一识别时保守返回 Unsupported。"""

    if not isinstance(output, str) or not output.strip():
        return HerdOutcome.UNSUPPORTED
    header = _HEADER_RE.search(output)
    if header is not None:
        return HerdOutcome(header.group(1).capitalize())
    confirmations = _CONDITION_RE.findall(output)
    if len(confirmations) == 1:
        return HerdOutcome.FORBIDDEN if confirmations[0] else HerdOutcome.ALLOWED
    return HerdOutcome.UNSUPPORTED


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _invocation(
    request: HerdOracleRequest,
    input_path: Path,
    model: str,
) -> HerdInvocation:
    command = (request.herd_executable, "-model", model, *request.extra_args, str(input_path))
    try:
        input_hash = _sha256(input_path)
    except (OSError, ValueError) as error:
        return HerdInvocation(
            input_path=str(input_path),
            model=model,
            command=command,
            status=HerdRunStatus.FAILED,
            outcome=HerdOutcome.UNSUPPORTED,
            returncode=None,
            stdout="",
            stderr="",
            input_sha256="",
            raw_output_sha256=hashlib.sha256(b"").hexdigest(),
            reason=f"cannot read herd input: {error}",
        )

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=request.timeout_seconds,
            env=dict(os.environ),
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, str) else ""
        stderr = error.stderr if isinstance(error.stderr, str) else ""
        return HerdInvocation(
            input_path=str(input_path),
            model=model,
            command=command,
            status=HerdRunStatus.TIMEOUT,
            outcome=HerdOutcome.UNSUPPORTED,
            returncode=None,
            stdout=stdout,
            stderr=stderr,
            input_sha256=input_hash,
            raw_output_sha256=hashlib.sha256(
                (stdout + "\0" + stderr).encode("utf-8", errors="replace")
            ).hexdigest(),
            reason=f"herd exceeded {request.timeout_seconds:g} seconds",
        )
    except OSError as error:
        return HerdInvocation(
            input_path=str(input_path),
            model=model,
            command=command,
            status=HerdRunStatus.FAILED,
            outcome=HerdOutcome.UNSUPPORTED,
            returncode=None,
            stdout="",
            stderr="",
            input_sha256=input_hash,
            raw_output_sha256=hashlib.sha256(b"").hexdigest(),
            reason=f"cannot execute herd: {error}",
        )

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    raw_hash = hashlib.sha256(
        (stdout + "\0" + stderr).encode("utf-8", errors="replace")
    ).hexdigest()
    if completed.returncode != 0:
        return HerdInvocation(
            input_path=str(input_path),
            model=model,
            command=command,
            status=HerdRunStatus.FAILED,
            outcome=HerdOutcome.UNSUPPORTED,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            input_sha256=input_hash,
            raw_output_sha256=raw_hash,
            reason=f"herd exited with status {completed.returncode}",
        )
    outcome = parse_herd_outcome(stdout + "\n" + stderr)
    status = (
        HerdRunStatus.COMPLETED
        if outcome is not HerdOutcome.UNSUPPORTED
        else HerdRunStatus.UNPARSED
    )
    reason = (
        "herd produced a recognized outcome"
        if status is HerdRunStatus.COMPLETED
        else "herd output did not contain one unambiguous outcome"
    )
    return HerdInvocation(
        input_path=str(input_path),
        model=model,
        command=command,
        status=status,
        outcome=outcome,
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        input_sha256=input_hash,
        raw_output_sha256=raw_hash,
        reason=reason,
    )


def run_herd_oracle(request: HerdOracleRequest) -> HerdOracleRun:
    """分别运行 source 与 contract-lowered target 的 herd 输入。"""

    return HerdOracleRun(
        request=request,
        source=_invocation(request, request.source_input, request.source_model),
        target=_invocation(request, request.target_input, request.target_model),
    )


def replay_herd_oracle(
    record: HerdOracleRecord,
    run: HerdOracleRun,
) -> HerdReplayResult:
    """比较已绑定记录与本次运行；任何绑定或运行缺口都不是 MATCH。"""

    differences: list[str] = []
    request = run.request
    if record.source_model != request.source_model:
        differences.append("source herd model does not match the oracle record")
    if record.target_model != request.target_model:
        differences.append("target herd model does not match the oracle record")
    if request.herd_version is not None and record.herd_version != request.herd_version:
        differences.append("herd version does not match the oracle record")
    if record.contract_version != request.contract_version:
        differences.append("DBT contract version does not match the oracle record")
    if record.contract_sha256 != request.contract_sha256:
        differences.append("DBT contract hash does not match the oracle record")
    if record.elf_sha256 != request.elf_sha256:
        differences.append("ELF hash does not match the oracle record")
    if record.source_input_sha256 != run.source.input_sha256:
        differences.append("source herd input hash does not match the oracle record")
    if record.target_input_sha256 != run.target.input_sha256:
        differences.append("target herd input hash does not match the oracle record")
    if record.source_outcome is not run.source.outcome:
        differences.append("source herd outcome changed")
    if record.target_outcome is not run.target.outcome:
        differences.append("target herd outcome changed")
    if record.raw_output_sha256 != run.raw_output_sha256:
        differences.append("herd raw output hash changed")
    if not run.complete:
        differences.append("source or target herd run is incomplete")
    if differences:
        status = (
            HerdReplayStatus.MISMATCH
            if run.complete and any(
                item.endswith("changed") for item in differences
            )
            else HerdReplayStatus.UNKNOWN
        )
    else:
        status = HerdReplayStatus.MATCH
    return HerdReplayResult(status=status, run=run, differences=tuple(dict.fromkeys(differences)))


__all__ = [
    "HerdInvocation",
    "HerdOracleRequest",
    "HerdOracleRun",
    "HerdReplayResult",
    "HerdReplayStatus",
    "HerdRunStatus",
    "parse_herd_outcome",
    "replay_herd_oracle",
    "run_herd_oracle",
]
