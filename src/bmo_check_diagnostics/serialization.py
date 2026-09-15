"""诊断快照和报告的显式 JSON 边界。

JSON 只在文件边界使用；业务代码仍然接收 canonical dataclass。读取时先重建
typed identity/evidence，再由 snapshot/report 构造器检查类别和依赖，避免把
任意字典直接当成 proof 或观察事实。
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from bmo_check_core import (
    AbstractObjectId,
    BasicBlockId,
    BinaryClosureId,
    CorrelationBinding,
    DiagnosticHint,
    DynamicDiagnosticSnapshot,
    EvidenceAttribute,
    EvidenceId,
    EvidenceSnapshot,
    FunctionId,
    InstructionId,
    MemoryEventId,
    MemoryOperandId,
    ModuleId,
    ObservedFact,
    ProducerId,
    ProofFact,
    StableId,
    StaticDiagnosticSnapshot,
    ThreadInstanceId,
    ThreadRoleId,
    TraceId,
    UnknownFact,
    UnknownKind,
    UnknownDischarge,
    CertificateVerdict,
)

from .correlation import (
    CorrelationKey,
    CorrelationRecord,
    CorrelationStatus,
    DiagnosticCorrelationReport,
)
from .report import (
    CertificateIdentity,
    DiagnosticCoverage,
    DiagnosticReport,
)


class DiagnosticSerializationError(ValueError):
    """JSON 文档不是当前 typed 诊断 schema 时抛出的错误。"""


_ID_TYPES: dict[str, type[StableId]] = {
    AbstractObjectId.prefix: AbstractObjectId,
    BasicBlockId.prefix: BasicBlockId,
    BinaryClosureId.prefix: BinaryClosureId,
    FunctionId.prefix: FunctionId,
    InstructionId.prefix: InstructionId,
    MemoryEventId.prefix: MemoryEventId,
    MemoryOperandId.prefix: MemoryOperandId,
    ModuleId.prefix: ModuleId,
    StableId.prefix: StableId,
    ThreadInstanceId.prefix: ThreadInstanceId,
    ThreadRoleId.prefix: ThreadRoleId,
    TraceId.prefix: TraceId,
}


def _object(name: str, value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DiagnosticSerializationError(f"{name} must be an object")
    return value


def _required(mapping: Mapping[str, Any], name: str) -> Any:
    if name not in mapping:
        raise DiagnosticSerializationError(f"missing required field: {name}")
    return mapping[name]


def _string(name: str, value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise DiagnosticSerializationError(f"{name} must be a non-empty string without NUL")
    return value


def _optional_string(name: str, value: object) -> str | None:
    if value is None:
        return None
    return _string(name, value)


def _string_list(name: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise DiagnosticSerializationError(f"{name} must be an array")
    return tuple(_string(name, item) for item in value)


def _stable_id(value: object, *, expected: type[StableId] | None = None) -> StableId:
    text = _string("stable identity", value)
    prefix, separator, _digest = text.partition(":")
    if not separator:
        raise DiagnosticSerializationError("stable identity has no type prefix")
    identity_type = expected or _ID_TYPES.get(prefix)
    if identity_type is None:
        raise DiagnosticSerializationError(f"unsupported stable identity prefix: {prefix}")
    if expected is not None and prefix != expected.prefix:
        raise DiagnosticSerializationError(
            f"stable identity prefix {prefix!r} does not match {expected.prefix!r}"
        )
    try:
        return identity_type.from_value(text)
    except ValueError as error:
        raise DiagnosticSerializationError(f"invalid stable identity: {text}") from error


def _evidence_id(value: object) -> EvidenceId:
    return _stable_id(value, expected=EvidenceId)  # type: ignore[return-value]


def _producer(value: object) -> ProducerId:
    mapping = _object("producer", value)
    return ProducerId(
        _string("producer name", _required(mapping, "name")),
        _string("producer version", _required(mapping, "version")),
    )


def _producer_payload(value: ProducerId) -> dict[str, str]:
    return {"name": value.name, "version": value.version}


def _subject(value: object) -> StableId | None:
    if value is None:
        return None
    return _stable_id(value)


def _attributes(value: object) -> tuple[EvidenceAttribute, ...]:
    if not isinstance(value, (list, tuple)):
        raise DiagnosticSerializationError("observed attributes must be an array")
    attributes: list[EvidenceAttribute] = []
    for item in value:
        mapping = _object("observed attribute", item)
        attributes.append(
            EvidenceAttribute(
                _string("attribute name", _required(mapping, "name")),
                _string("attribute value", _required(mapping, "value")),
            )
        )
    return tuple(attributes)


def _node_payload(node: ProofFact | ObservedFact | DiagnosticHint | UnknownFact) -> dict[str, Any]:
    common: dict[str, Any] = {
        "id": node.id.value,
        "schema_version": node.schema_version,
        "producer": _producer_payload(node.producer),
    }
    if isinstance(node, ProofFact):
        return {
            **common,
            "category": "ProofFact",
            "subject": node.subject.value if node.subject else None,
            "rule": node.rule,
            "scope": node.scope,
            "premises": [item.value for item in node.premises],
            "covered_events": [item.value for item in node.covered_events],
        }
    if isinstance(node, ObservedFact):
        return {
            **common,
            "category": "ObservedFact",
            "trace_id": node.trace_id.value,
            "execution_id": node.execution_id.value,
            "subject": node.subject.value if node.subject else None,
            "observation_kind": node.observation_kind,
            "attributes": [
                {"name": item.name, "value": item.value}
                for item in node.attributes
            ],
        }
    if isinstance(node, DiagnosticHint):
        return {
            **common,
            "category": "DiagnosticHint",
            "scope": node.scope,
            "unknown_ids": [item.value for item in node.unknown_ids],
            "observed_ids": [item.value for item in node.observed_ids],
            "root_cause": node.root_cause,
            "confidence": node.confidence,
            "explanation": node.explanation,
        }
    return {
        **common,
        "category": "UnknownFact",
        "kind": node.kind.value,
        "reason": node.reason,
        "subject": node.subject.value if node.subject else None,
        "scope": node.scope,
        "provenance": [item.value for item in node.provenance],
        "supporting_context": list(node.supporting_context),
    }


def _node(mapping_value: object) -> ProofFact | ObservedFact | DiagnosticHint | UnknownFact:
    mapping = _object("evidence node", mapping_value)
    category = _string("evidence category", _required(mapping, "category"))
    schema_version = _string("evidence schema_version", _required(mapping, "schema_version"))
    producer = _producer(_required(mapping, "producer"))
    supplied_id = _evidence_id(_required(mapping, "id"))
    if category == "ProofFact":
        node = ProofFact.create(
            schema_version=schema_version,
            producer=producer,
            subject=_subject(_required(mapping, "subject")),
            rule=_string("proof rule", _required(mapping, "rule")),
            scope=_string("proof scope", _required(mapping, "scope")),
            premises=tuple(
                _evidence_id(item)
                for item in _required(mapping, "premises")
            ),
            covered_events=tuple(
                _stable_id(item, expected=MemoryEventId)  # type: ignore[arg-type]
                for item in _required(mapping, "covered_events")
            ),
        )
    elif category == "ObservedFact":
        trace_id = _stable_id(_required(mapping, "trace_id"), expected=TraceId)
        execution_id = _stable_id(
            _required(mapping, "execution_id"), expected=ThreadInstanceId
        )
        node = ObservedFact.create(
            schema_version=schema_version,
            producer=producer,
            trace_id=trace_id,  # type: ignore[arg-type]
            execution_id=execution_id,  # type: ignore[arg-type]
            subject=_subject(_required(mapping, "subject")),
            observation_kind=_string(
                "observation kind", _required(mapping, "observation_kind")
            ),
            attributes=_attributes(_required(mapping, "attributes")),
        )
    elif category == "DiagnosticHint":
        confidence = _required(mapping, "confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise DiagnosticSerializationError("diagnostic confidence must be a number")
        node = DiagnosticHint.create(
            schema_version=schema_version,
            producer=producer,
            scope=_string("diagnostic scope", _required(mapping, "scope")),
            unknown_ids=tuple(
                _evidence_id(item) for item in _required(mapping, "unknown_ids")
            ),
            observed_ids=tuple(
                _evidence_id(item) for item in _required(mapping, "observed_ids")
            ),
            root_cause=_string("diagnostic root cause", _required(mapping, "root_cause")),
            confidence=float(confidence),
            explanation=_string("diagnostic explanation", _required(mapping, "explanation")),
        )
    elif category == "UnknownFact":
        try:
            kind = UnknownKind(_string("unknown kind", _required(mapping, "kind")))
        except ValueError as error:
            raise DiagnosticSerializationError("unknown kind is not registered") from error
        node = UnknownFact.create(
            schema_version=schema_version,
            producer=producer,
            kind=kind,
            reason=_string("unknown reason", _required(mapping, "reason")),
            subject=_subject(_required(mapping, "subject")),
            scope=_string("unknown scope", _required(mapping, "scope")),
            provenance=tuple(
                _evidence_id(item) for item in _required(mapping, "provenance")
            ),
            supporting_context=_string_list(
                "supporting_context", _required(mapping, "supporting_context")
            ),
        )
    else:
        raise DiagnosticSerializationError(f"unsupported evidence category: {category}")
    if node.id != supplied_id:
        raise DiagnosticSerializationError(
            f"evidence id/content mismatch for {supplied_id.value}"
        )
    return node


def _discharge(value: object) -> UnknownDischarge:
    mapping = _object("evidence discharge", value)
    return UnknownDischarge(
        unknown_id=_evidence_id(_required(mapping, "unknown_id")),
        proof_id=_evidence_id(_required(mapping, "proof_id")),
        scope=_string("discharge scope", _required(mapping, "scope")),
    )


def _evidence_payload(snapshot: StaticDiagnosticSnapshot | DynamicDiagnosticSnapshot) -> dict[str, Any]:
    return {
        "nodes": [_node_payload(item) for item in snapshot.evidence.nodes],
        "discharges": [
            {
                "unknown_id": item.unknown_id.value,
                "proof_id": item.proof_id.value,
                "scope": item.scope,
            }
            for item in snapshot.evidence.discharges
        ],
    }


def snapshot_to_dict(
    snapshot: StaticDiagnosticSnapshot | DynamicDiagnosticSnapshot,
) -> dict[str, Any]:
    """将 canonical snapshot 转成 versioned JSON-compatible 文档。"""

    if isinstance(snapshot, StaticDiagnosticSnapshot):
        payload = {
            "kind": "static",
            "schema_version": snapshot.schema_version,
            "scope": snapshot.scope,
            "verdict": snapshot.verdict.value,
            "binary_closure": snapshot.binary_closure.value
            if snapshot.binary_closure
            else None,
            "subject_ids": [item.value for item in snapshot.subject_ids],
            "evidence": _evidence_payload(snapshot),
        }
        if snapshot.blocking_unknown_ids is not None:
            payload["blocking_unknown_ids"] = [
                item.value for item in snapshot.blocking_unknown_ids
            ]
        return payload
    if isinstance(snapshot, DynamicDiagnosticSnapshot):
        return {
            "kind": "dynamic",
            "schema_version": snapshot.schema_version,
            "trace_id": snapshot.trace_id.value,
            "scope": snapshot.scope,
            "complete": snapshot.complete,
            "binary_closure": snapshot.binary_closure.value
            if snapshot.binary_closure
            else None,
            "evidence": _evidence_payload(snapshot),
        }
    raise DiagnosticSerializationError("unsupported snapshot type")


def snapshot_from_dict(
    payload: object,
    *,
    expected_kind: str | None = None,
) -> StaticDiagnosticSnapshot | DynamicDiagnosticSnapshot:
    mapping = _object("snapshot", payload)
    kind = _string("snapshot kind", _required(mapping, "kind"))
    if expected_kind is not None and kind != expected_kind:
        raise DiagnosticSerializationError(
            f"expected {expected_kind} snapshot, got {kind}"
        )
    schema_version = _string("snapshot schema_version", _required(mapping, "schema_version"))
    scope = _string("snapshot scope", _required(mapping, "scope"))
    evidence_mapping = _object("snapshot evidence", _required(mapping, "evidence"))
    raw_nodes = _required(evidence_mapping, "nodes")
    raw_discharges = _required(evidence_mapping, "discharges")
    if not isinstance(raw_nodes, (list, tuple)) or not isinstance(raw_discharges, (list, tuple)):
        raise DiagnosticSerializationError("snapshot evidence nodes/discharges must be arrays")
    evidence = EvidenceSnapshot(
        nodes=tuple(_node(item) for item in raw_nodes),
        discharges=tuple(_discharge(item) for item in raw_discharges),
    )
    closure_value = mapping.get("binary_closure")
    closure = (
        _stable_id(closure_value, expected=BinaryClosureId)  # type: ignore[arg-type]
        if closure_value is not None
        else None
    )
    if kind == "static":
        try:
            verdict = CertificateVerdict(
                _string("static verdict", _required(mapping, "verdict"))
            )
        except ValueError as error:
            raise DiagnosticSerializationError("invalid static verdict") from error
        raw_subjects = _required(mapping, "subject_ids")
        if not isinstance(raw_subjects, (list, tuple)):
            raise DiagnosticSerializationError("subject_ids must be an array")
        if "blocking_unknown_ids" not in mapping:
            if schema_version != "static-diagnostic-v1":
                raise DiagnosticSerializationError(
                    "static snapshot schema requires blocking_unknown_ids"
                )
            blocking_unknown_ids = None
        else:
            raw_blockers = mapping["blocking_unknown_ids"]
            if not isinstance(raw_blockers, (list, tuple)):
                raise DiagnosticSerializationError("blocking_unknown_ids must be an array")
            blocking_unknown_ids = tuple(_evidence_id(item) for item in raw_blockers)
        return StaticDiagnosticSnapshot(
            schema_version=schema_version,
            scope=scope,
            verdict=verdict,
            evidence=evidence,
            binary_closure=closure,  # type: ignore[arg-type]
            subject_ids=tuple(_stable_id(item) for item in raw_subjects),
            blocking_unknown_ids=blocking_unknown_ids,
        )
    if kind == "dynamic":
        trace_id = _stable_id(_required(mapping, "trace_id"), expected=TraceId)
        complete = _required(mapping, "complete")
        if not isinstance(complete, bool):
            raise DiagnosticSerializationError("dynamic complete must be boolean")
        return DynamicDiagnosticSnapshot(
            schema_version=schema_version,
            trace_id=trace_id,  # type: ignore[arg-type]
            scope=scope,
            complete=complete,
            evidence=evidence,
            binary_closure=closure,  # type: ignore[arg-type]
        )
    raise DiagnosticSerializationError(f"unsupported snapshot kind: {kind}")


def snapshot_to_json(snapshot: StaticDiagnosticSnapshot | DynamicDiagnosticSnapshot) -> str:
    return json.dumps(snapshot_to_dict(snapshot), ensure_ascii=False, indent=2, sort_keys=True)


def snapshot_from_json(
    payload: str,
    *,
    expected_kind: str | None = None,
) -> StaticDiagnosticSnapshot | DynamicDiagnosticSnapshot:
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as error:
        raise DiagnosticSerializationError(f"invalid snapshot JSON: {error}") from error
    return snapshot_from_dict(value, expected_kind=expected_kind)


def load_snapshot(
    path: Path,
    *,
    expected_kind: str | None = None,
) -> StaticDiagnosticSnapshot | DynamicDiagnosticSnapshot:
    try:
        return snapshot_from_json(path.read_text(encoding="utf-8"), expected_kind=expected_kind)
    except OSError as error:
        raise DiagnosticSerializationError(f"cannot read snapshot {path}: {error}") from error


def save_snapshot(
    snapshot: StaticDiagnosticSnapshot | DynamicDiagnosticSnapshot,
    path: Path,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(snapshot_to_json(snapshot) + "\n", encoding="utf-8")


def _identity_payload(identity: CertificateIdentity) -> dict[str, Any]:
    return {
        "kind": identity.kind,
        "certificate_id": identity.certificate_id,
        "schema_version": identity.schema_version,
        "binary_closure": identity.binary_closure.value
        if identity.binary_closure
        else None,
        "trace_id": identity.trace_id.value if identity.trace_id else None,
        "artifact_sha256": identity.artifact_sha256,
        "scope": identity.scope,
    }


def _correlation_payload(
    correlation: DiagnosticCorrelationReport,
) -> dict[str, Any]:
    return {
        "schema_version": correlation.schema_version,
        "static_verdict": correlation.static_verdict.value,
        "trace_id": correlation.trace_id.value,
        "trace_complete": correlation.trace_complete,
        "binding": _binding_payload(correlation.binding),
        "records": [
            {
                "unknown_id": item.unknown_id.value,
                "observed_ids": [value.value for value in item.observed_ids],
                "status": item.status.value,
                "key": item.key.value,
                "reason": item.reason,
            }
            for item in correlation.records
        ],
    }


def _binding_payload(binding: CorrelationBinding | None) -> dict[str, Any] | None:
    if binding is None:
        return None
    return {
        "status": binding.status.value,
        "checks": [
            {
                "dimension": item.dimension.value,
                "status": item.status.value,
                "reason": item.reason,
            }
            for item in binding.checks
        ],
    }


def report_to_dict(report: DiagnosticReport) -> dict[str, Any]:
    """将报告序列化为可审计 JSON；不把它降格成 proof certificate。"""

    if not isinstance(report, DiagnosticReport):
        raise DiagnosticSerializationError("unsupported diagnostic report type")
    return {
        "schema_version": report.schema_version,
        "static_verdict": report.static_verdict.value,
        "static_certificate": _identity_payload(report.static_certificate),
        "trace_certificate": _identity_payload(report.trace_certificate),
        "static_snapshot_schema_version": report.static_snapshot_schema_version,
        "dynamic_snapshot_schema_version": report.dynamic_snapshot_schema_version,
        "trace_id": report.trace_id.value,
        "trace_complete": report.trace_complete,
        "blocking_unknowns": [_node_payload(item) for item in report.blocking_unknowns],
        "selected_unknowns": [_node_payload(item) for item in report.selected_unknowns],
        "discharged_unknowns": [_node_payload(item) for item in report.discharged_unknowns],
        "correlations": _correlation_payload(report.correlations),
        "observed_facts": [_node_payload(item) for item in report.observed_facts],
        "dynamic_unknowns": [_node_payload(item) for item in report.dynamic_unknowns],
        "coverage": {
            "observed_fact_count": report.coverage.observed_fact_count,
            "observed_unknown_count": report.coverage.observed_unknown_count,
            "observed_subject_count": report.coverage.observed_subject_count,
            "observed_thread_count": report.coverage.observed_thread_count,
            "blocking_unknown_count": report.coverage.blocking_unknown_count,
            "discharged_unknown_count": report.coverage.discharged_unknown_count,
            "selected_unknown_count": report.coverage.selected_unknown_count,
            "exact_count": report.coverage.exact_count,
            "ambiguous_count": report.coverage.ambiguous_count,
            "unmatched_count": report.coverage.unmatched_count,
        },
        "hints": [_node_payload(item) for item in report.hints],
        "static_proof_unchanged": report.static_proof_unchanged,
        "statement": report.statement,
    }


def report_to_json(report: DiagnosticReport) -> str:
    return json.dumps(report_to_dict(report), ensure_ascii=False, indent=2, sort_keys=True)


def save_report(report: DiagnosticReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_to_json(report) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    """计算 artifact identity；路径本身不参与证书绑定。"""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise DiagnosticSerializationError(f"cannot hash artifact {path}: {error}") from error
    return digest.hexdigest()


__all__ = [
    "DiagnosticSerializationError",
    "load_snapshot",
    "report_to_dict",
    "report_to_json",
    "save_report",
    "save_snapshot",
    "sha256_file",
    "snapshot_from_dict",
    "snapshot_from_json",
    "snapshot_to_dict",
    "snapshot_to_json",
]
