"""把版本化 litmus manifest 接入普通 static recovery pipeline。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from bmo_check_static.application import StaticRequest, slice_report
from bmo_check_static.config import load_canonical_contract
from bmo_check_static.model import ProgramSliceReport
from bmo_check_static.proof.characterization import (
    FixedExecutionResult as StaticExecutionResult,
    check_fixed_execution,
)
from bmo_check_static.proof.encoding import _object_id

from .conformance import (
    ConformanceResult,
    ConformanceStatus,
    align_critical_events,
)
from .model import ExecutionAssignment, LitmusCase, LitmusManifest


class LitmusServiceError(ValueError):
    """manifest 或 service 参数无法形成一次可复现 conformance 请求。"""


@dataclass(frozen=True, slots=True)
class LitmusConformanceRequest:
    """一次 litmus ELF conformance 的显式输入边界。"""

    manifest: Path
    corpus_root: Path
    dbt_contract: Path
    pthread_spec: Path
    function_effects: Path
    library_roots: tuple[Path, ...] = ()
    dbt_revision: str | None = None
    scope: str = "full"
    max_extra_event_ids: int = 32

    def __post_init__(self) -> None:
        for name in (
            "manifest",
            "corpus_root",
            "dbt_contract",
            "pthread_spec",
            "function_effects",
        ):
            if not isinstance(getattr(self, name), Path):
                raise LitmusServiceError(f"{name} must be a Path")
        if self.scope not in {"full", "application"}:
            raise LitmusServiceError("scope must be 'full' or 'application'")
        if self.max_extra_event_ids < 0:
            raise LitmusServiceError("max_extra_event_ids must be non-negative")


@dataclass(frozen=True, slots=True)
class ExecutionLegalityRecord:
    """一个 manifest execution assignment 的静态 source/target 结果。"""

    assignment_id: str
    source_status: str
    target_status: str
    source_reason: str
    target_reason: str


@dataclass(frozen=True, slots=True)
class LitmusCaseConformance:
    """单个真实 ELF 的恢复、对象和固定 execution 结果。"""

    case_id: str
    status: ConformanceStatus
    elf_path: str
    source_path: str
    conformance: ConformanceResult | None = None
    executions: tuple[ExecutionLegalityRecord, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LitmusConformanceReport:
    """E2.5 report；不把 conformance 状态冒充 SAFE/TRACE_SAFE。"""

    manifest_path: str
    corpus_name: str
    corpus_revision: str
    contract_version: str
    contract_sha256: str | None
    cases: tuple[LitmusCaseConformance, ...]

    @property
    def status(self) -> ConformanceStatus:
        if not self.cases or any(case.status is not ConformanceStatus.MATCHED for case in self.cases):
            return ConformanceStatus.UNKNOWN
        return ConformanceStatus.MATCHED


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve(root: Path, relative: str) -> Path:
    candidate = (root / Path(relative)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise LitmusServiceError(f"manifest path escapes corpus root: {relative}") from error
    return candidate


def _path_errors(case: LitmusCase, root: Path) -> tuple[Path, Path, tuple[str, ...]]:
    source = _resolve(root, case.binding.source_litmus)
    elf = _resolve(root, case.binding.elf_relative_path)
    errors: list[str] = []
    for path, expected, label in (
        (source, case.binding.source_sha256, "source litmus"),
        (elf, case.binding.elf_sha256, "ELF"),
    ):
        if not path.is_file():
            errors.append(f"{label} does not exist: {path}")
            continue
        actual = _sha256(path)
        if actual != expected:
            errors.append(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")
    return source, elf, tuple(errors)


def _execution_record(
    case: LitmusCase,
    conformance: ConformanceResult,
    report: ProgramSliceReport,
    assignment: ExecutionAssignment,
) -> ExecutionLegalityRecord:
    matches = {match.label: match.event_id for match in conformance.matches}
    read_from: dict[str, str | None] = {}
    for choice in assignment.read_from:
        if choice.load not in matches or (
            choice.store is not None and choice.store not in matches
        ):
            return ExecutionLegalityRecord(
                assignment_id=assignment.assignment_id,
                source_status="unknown",
                target_status="unknown",
                source_reason="execution relation references an unmatched critical event",
                target_reason="execution relation references an unmatched critical event",
            )
        read_from[matches[choice.load]] = (
            matches[choice.store] if choice.store is not None else None
        )

    event_by_id = {event.id: event for event in report.shared_slice.events}
    object_ids: dict[str, str] = {}
    for critical in case.critical_events:
        if critical.object_label is None or critical.label not in matches:
            continue
        event = event_by_id[matches[critical.label]]
        if event.address is None:
            return ExecutionLegalityRecord(
                assignment_id=assignment.assignment_id,
                source_status="unknown",
                target_status="unknown",
                source_reason="critical object has no recovered address",
                target_reason="critical object has no recovered address",
            )
        object_ids[critical.object_label] = _object_id(event)

    coherence: list[tuple[str, str, str]] = []
    for pair in assignment.coherence:
        if pair.object_label not in object_ids or pair.before not in matches or pair.after not in matches:
            return ExecutionLegalityRecord(
                assignment_id=assignment.assignment_id,
                source_status="unknown",
                target_status="unknown",
                source_reason="coherence relation references an unmatched object or event",
                target_reason="coherence relation references an unmatched object or event",
            )
        coherence.append(
            (object_ids[pair.object_label], matches[pair.before], matches[pair.after])
        )
    result: StaticExecutionResult = check_fixed_execution(
        report.shared_slice,
        read_from=read_from,
        coherence=tuple(coherence),
    )
    return ExecutionLegalityRecord(
        assignment_id=assignment.assignment_id,
        source_status=result.source.status,
        target_status=result.target.status,
        source_reason=result.source.reason,
        target_reason=result.target.reason,
    )


def _unknown_case(
    case: LitmusCase,
    source: Path,
    elf: Path,
    errors: tuple[str, ...],
) -> LitmusCaseConformance:
    return LitmusCaseConformance(
        case_id=case.case_id,
        status=ConformanceStatus.UNKNOWN,
        elf_path=str(elf),
        source_path=str(source),
        errors=errors,
    )


def run_litmus_conformance(request: LitmusConformanceRequest) -> LitmusConformanceReport:
    """逐 case 校验绑定后调用普通 static recovery，并检查固定 executions。"""

    from .model import load_manifest

    manifest: LitmusManifest = load_manifest(request.manifest)
    contract = load_canonical_contract(request.dbt_contract)
    if contract.unknown is not None:
        cases = tuple(
            _unknown_case(
                case,
                request.corpus_root / case.binding.source_litmus,
                request.corpus_root / case.binding.elf_relative_path,
                (contract.unknown.reason,),
            )
            for case in manifest.cases
        )
        return LitmusConformanceReport(
            manifest_path=str(request.manifest),
            corpus_name=manifest.corpus_name,
            corpus_revision=manifest.corpus_revision,
            contract_version=contract.version,
            contract_sha256=contract.sha256,
            cases=cases,
        )

    cases: list[LitmusCaseConformance] = []
    for case in manifest.cases:
        if (
            case.oracle.contract_version != contract.version
            or case.oracle.contract_sha256 != contract.sha256
        ):
            cases.append(
                _unknown_case(
                    case,
                    request.corpus_root / Path(case.binding.source_litmus),
                    request.corpus_root / Path(case.binding.elf_relative_path),
                    (
                        "case oracle is bound to a different DBT lowering contract",
                    ),
                )
            )
            continue
        source, elf, errors = _path_errors(case, request.corpus_root)
        if errors:
            cases.append(_unknown_case(case, source, elf, errors))
            continue
        static_request = StaticRequest(
            executable=elf,
            dbt_contract=request.dbt_contract,
            pthread_spec=request.pthread_spec,
            function_effects=request.function_effects,
            library_roots=request.library_roots,
            dbt_revision=request.dbt_revision,
            scope=request.scope,
        )
        try:
            recovered = slice_report(static_request)
            executable = recovered.recovery.manifest.executable
            if executable is None or executable.sha256 != case.binding.elf_sha256:
                cases.append(
                    _unknown_case(
                        case,
                        source,
                        elf,
                        ("static recovery report is bound to a different ELF",),
                    )
                )
                continue
            conformance = align_critical_events(
                case,
                recovered,
                max_extra_event_ids=request.max_extra_event_ids,
            )
            executions = (
                tuple(
                    _execution_record(case, conformance, recovered, assignment)
                    for assignment in case.executions
                )
                if conformance.status is ConformanceStatus.MATCHED
                and recovered.shared_slice is not None
                else ()
            )
            errors = conformance.reasons
            if any(
                record.source_status == "unknown" or record.target_status == "unknown"
                for record in executions
            ):
                errors = (*errors, "one or more fixed executions are unknown")
            status = (
                ConformanceStatus.MATCHED
                if conformance.status is ConformanceStatus.MATCHED and not errors
                else ConformanceStatus.UNKNOWN
            )
            cases.append(
                LitmusCaseConformance(
                    case_id=case.case_id,
                    status=status,
                    elf_path=str(elf),
                    source_path=str(source),
                    conformance=conformance,
                    executions=executions,
                    errors=tuple(dict.fromkeys(errors)),
                )
            )
        except Exception as error:
            cases.append(
                _unknown_case(
                    case,
                    source,
                    elf,
                    (f"static conformance pipeline failed: {error}",),
                )
            )
    return LitmusConformanceReport(
        manifest_path=str(request.manifest),
        corpus_name=manifest.corpus_name,
        corpus_revision=manifest.corpus_revision,
        contract_version=contract.version,
        contract_sha256=contract.sha256,
        cases=tuple(cases),
    )


__all__ = [
    "ExecutionLegalityRecord",
    "LitmusCaseConformance",
    "LitmusConformanceReport",
    "LitmusConformanceRequest",
    "LitmusServiceError",
    "run_litmus_conformance",
]
