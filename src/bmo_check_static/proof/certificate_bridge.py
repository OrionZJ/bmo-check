"""把旧静态 verdict 接到 canonical static certificate。

旧 portability checker 仍是事实和 verdict 的来源；本模块只在证书边界
把已经生成的 typed sidecar 组装起来，并立即 replay。这样迁移期间不会
出现一份没有 proof closure 的“新 SAFE”证书。
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from bmo_check_core import (
    BinaryClosureId,
    CertificateBinding,
    CertificateError,
    CertificateVerdict,
    EvidenceLedger,
    EvidenceId,
    MemoryEventId,
    ObservedFact,
    DiagnosticHint,
    StaticCertificate,
    StaticVerification,
    UnknownFact as CanonicalUnknownFact,
    ProofFact,
    RemovalDecision,
    UnknownDischarge,
    verify_static_certificate,
)
from bmo_check_static.binary.evidence import emit_static_unknown
from bmo_check_static.model import (
    ModuleRole,
    PortabilityCertificate,
    ProgramManifest,
    ProgramSliceReport,
    PruningCoverage,
    ProofObject,
    SharedMemorySlice,
)

from ..slicing.evidence import SliceProofLink, StaticSliceEvidence
from .evidence import StaticPortabilityEvidence


class CertificateBridgeError(CertificateError):
    """sidecar 无法在同一个静态证书 scope 内闭合时抛出。"""


@dataclass(frozen=True, slots=True)
class StaticCertificateEvidence:
    # certificate 是 replay 后才可交给序列化层的 canonical 证书。
    certificate: StaticCertificate
    # ledger 保留证书 closure 和相关 Unknown，供解释器再次检查。
    ledger: EvidenceLedger
    # verification 保存本次构造时的 replay 结果，避免调用者跳过门禁。
    verification: StaticVerification


def binding_from_manifest(
    manifest: ProgramManifest,
    *,
    scope: str,
    abi: str | None = None,
) -> CertificateBinding:
    """从恢复 manifest 生成稳定的 binary/DBT 绑定。

    路径和遍历顺序不属于绑定身份；缺少 executable 或 DBT revision 时直接
    拒绝，因为这些字段缺失不能安全地解释旧 proof 的适用范围。
    """

    if manifest.executable is None:
        raise CertificateBridgeError("static certificate requires an executable")
    if not manifest.dbt_revision:
        raise CertificateBridgeError("static certificate requires a DBT revision")
    executable = manifest.executable
    modules: list[tuple[str, str]] = [
        (ModuleRole.EXECUTABLE.value, executable.sha256),
    ]
    if manifest.interpreter is not None:
        modules.append((ModuleRole.INTERPRETER.value, manifest.interpreter.sha256))
    modules.extend(
        (ModuleRole.SHARED_LIBRARY.value, module.sha256)
        for module in manifest.libraries
    )
    machine_abi = abi or (
        f"{executable.elf.machine}:elf{executable.elf.elf_class}:"
        f"{'le' if executable.elf.little_endian else 'be'}"
    )
    return CertificateBinding(
        binary_closure=BinaryClosureId.from_parts(
            executable.sha256,
            modules,
            machine_abi,
        ),
        dbt_contract_version=manifest.dbt_contract_version,
        dbt_revision=manifest.dbt_revision,
        scope=scope,
    )


def _merge_ledgers(*ledgers: EvidenceLedger) -> EvidenceLedger:
    merged = EvidenceLedger()
    for ledger in ledgers:
        for node in ledger.nodes():
            merged.add(node)
        for discharge in ledger.discharges():
            merged.add_discharge(discharge)
    return merged


def _validate_static_nodes(ledger: EvidenceLedger, scope: str) -> None:
    """拒绝把动态观察或另一个 scope 的事实偷偷拼进证书。"""

    for node in ledger.nodes():
        if isinstance(node, (ObservedFact, DiagnosticHint)):
            raise CertificateBridgeError(
                "static certificate ledger cannot contain dynamic observations or hints"
            )
        if isinstance(node, (ProofFact, CanonicalUnknownFact)) and node.scope != scope:
            raise CertificateBridgeError(
                "all static certificate evidence must use the certificate scope"
            )


def build_static_certificate_with_evidence(
    slice_evidence: StaticSliceEvidence,
    portability_evidence: StaticPortabilityEvidence,
    binding: CertificateBinding,
    *,
    schema_version: str = "static-certificate-1",
) -> StaticCertificateEvidence:
    """把旧 portability 结论转换为经过 replay 的 canonical 证书。

    调用者必须让各 sidecar 在生成时使用同一个 ``binding.scope``。拒绝
    自动重写 scope，是为了避免把一个分析范围的 Unknown 当成另一个范围
    已解决；需要新范围时应重新运行对应 producer。
    """

    if not isinstance(slice_evidence, StaticSliceEvidence):
        raise CertificateBridgeError("slice_evidence has an invalid type")
    if not isinstance(portability_evidence, StaticPortabilityEvidence):
        raise CertificateBridgeError("portability_evidence has an invalid type")
    if not isinstance(binding, CertificateBinding):
        raise CertificateBridgeError("binding has an invalid type")
    ledger = _merge_ledgers(slice_evidence.ledger, portability_evidence.ledger)
    _validate_static_nodes(ledger, binding.scope)

    try:
        verdict = CertificateVerdict(portability_evidence.certificate.verdict.value)
    except ValueError as error:
        raise CertificateBridgeError("legacy certificate has an unknown verdict") from error

    unknown_ids = tuple(
        node.id
        for node in ledger.unresolved_unknowns(binding.scope)
    )
    certificate = StaticCertificate(
        schema_version=schema_version,
        verdict=verdict,
        binding=binding,
        proof_roots=slice_evidence.proof_ids,
        removal_decisions=slice_evidence.removal_decisions,
        relevant_unknowns=unknown_ids,
        bounded=portability_evidence.certificate.checker.bounded,
    )
    try:
        verification = verify_static_certificate(
            certificate,
            ledger,
            expected_binding=binding,
        )
    except CertificateError as error:
        raise CertificateBridgeError(
            f"canonical static certificate replay failed: {error}"
        ) from error
    return StaticCertificateEvidence(
        certificate=certificate,
        ledger=ledger,
        verification=verification,
    )


def build_static_certificate_from_report(
    report: ProgramSliceReport,
    portability_certificate: PortabilityCertificate,
    binding: CertificateBinding,
    *,
    schema_version: str = "static-certificate-1",
) -> StaticCertificateEvidence:
    """把一次旧静态分析结果接入 canonical replay。

    旧分析器仍负责生成报告和决定哪些 Unknown 与当前 scope 相关；这里把
    报告中的 proof object 转成 ``ProofFact``，把最终相关 Unknown 重新写入
    同一个 ledger，然后交给唯一的 canonical verifier。这样旧 JSON 可以
    继续被调用者读取，但 SAFE 不再绕过 proof-closure 检查。

    报告中的 Unknown 会先全部进入 canonical ledger。只有能由同一 scope
    下的 ProofFact 覆盖其事件时，才记录显式 ``UnknownDischarge``；旧 verifier
    额外生成、但报告中没有来源的最终 Unknown 也会被补入 ledger。这样旧的
    relevance 过滤不会把未证明的 obligation 静默丢掉。
    """

    if not isinstance(report, ProgramSliceReport):
        raise CertificateBridgeError("report has an invalid type")
    if not isinstance(portability_certificate, PortabilityCertificate):
        raise CertificateBridgeError(
            "portability_certificate has an invalid type"
        )
    if not isinstance(binding, CertificateBinding):
        raise CertificateBridgeError("binding has an invalid type")

    # 延迟导入避免 adapters.__init__ -> diagnostic_snapshot -> bridge 的循环。
    from bmo_check_static.adapters.evidence import (
        adapt_static_report,
        legacy_unknown_key,
    )

    snapshot = adapt_static_report(report, scope=binding.scope)
    proof_nodes = tuple(
        node
        for node in snapshot.ledger.nodes()
        if isinstance(node, (ProofFact, CanonicalUnknownFact))
    )
    proof_ledger = EvidenceLedger()
    for node in proof_nodes:
        proof_ledger.add(node)

    event_ids = {
        link.legacy_id: link.canonical_id
        for link in snapshot.event_links
        if isinstance(link.canonical_id, MemoryEventId)
    }
    proof_ids = {
        link.legacy_id: link.canonical_id
        for link in snapshot.proof_links
        if isinstance(link.canonical_id, EvidenceId)
    }

    # removal_decisions 必须逐事件绑定到可回放的 ProofFact；不再依赖旧的
    # 字符串 ID 是否“看起来像”同一事件。
    decisions: list[RemovalDecision] = []
    removed_event_ids = (
        report.shared_state.removed_event_ids
        if report.shared_state is not None
        else ()
    )
    proof_models: list[ProofObject] = []
    if report.shared_state is not None:
        proof_models.extend(report.shared_state.proofs)
    if report.shared_slice is not None:
        proof_models.extend(report.shared_slice.proof_objects)
    for legacy_event_id in removed_event_ids:
        event_id = event_ids.get(legacy_event_id)
        if event_id is None:
            raise CertificateBridgeError(
                f"removed event {legacy_event_id!r} has no canonical identity"
            )
        covering = tuple(
            proof_ids[proof.id]
            for proof in proof_models
            if legacy_event_id in proof.event_ids and proof.id in proof_ids
        )
        if not covering:
            raise CertificateBridgeError(
                f"removed event {legacy_event_id!r} has no canonical proof"
            )
        decisions.append(
            RemovalDecision(
                event_id=event_id,
                proof_id=covering[0],
                scope=binding.scope,
            )
        )

    relevant_unknown_keys = {
        legacy_unknown_key(unknown)
        for unknown in portability_certificate.relevant_unknowns
    }
    snapshot_unknown_keys = {
        link.legacy_id for link in snapshot.unknown_links
    }

    # 报告里的 Unknown 不能因为旧 verifier 的过滤就凭空消失。只有它明确
    # 指向一个已被 ProofFact 覆盖的事件时，才追加可回放的 discharge；其余
    # Unknown 会继续作为 canonical certificate 的 unresolved obligation。
    for link in snapshot.unknown_links:
        if link.legacy_id in relevant_unknown_keys:
            continue
        node = proof_ledger.get(link.canonical_id)
        if not isinstance(node, CanonicalUnknownFact):
            continue
        event_ids_for_unknown: set[MemoryEventId] = set()
        if isinstance(node.subject, MemoryEventId):
            event_ids_for_unknown.add(node.subject)
        for context in link.context:
            prefix = "legacy.detail."
            if not context.startswith(prefix):
                continue
            key, _, encoded = context[len(prefix) :].partition("=")
            if key not in {"event_id", "event_ids"}:
                continue
            try:
                value = json.loads(encoded)
            except json.JSONDecodeError:
                continue
            values = [value] if key == "event_id" else value
            if not isinstance(values, list):
                continue
            for legacy_event_id in values:
                if legacy_event_id in event_ids:
                    event_ids_for_unknown.add(event_ids[legacy_event_id])
        if not event_ids_for_unknown:
            continue
        covering = next(
            (
                proof
                for proof in proof_nodes
                if isinstance(proof, ProofFact)
                and event_ids_for_unknown.issubset(set(proof.covered_events))
            ),
            None,
        )
        if covering is not None:
            proof_ledger.add_discharge(
                UnknownDischarge(node.id, covering.id, binding.scope)
            )

    portability_ledger = EvidenceLedger()
    for unknown in portability_certificate.relevant_unknowns:
        # report adapter 已经保留了同一 legacy Unknown 时复用它的 canonical
        # 节点；否则补上 checker 在报告之外生成的最终 Unknown。
        if legacy_unknown_key(unknown) in snapshot_unknown_keys:
            continue
        emit_static_unknown(
            unknown.kind,
            unknown.reason,
            unknown.impact,
            module=unknown.module,
            pc=unknown.pc,
            function=unknown.function,
            details=unknown.details,
            canonical_ledger=portability_ledger,
            canonical_scope=binding.scope,
        )

    slice_evidence = StaticSliceEvidence(
        report=(
            report.shared_slice
            if report.shared_slice is not None
            else SharedMemorySlice(coverage=PruningCoverage(total_events=0))
        ),
        ledger=proof_ledger,
        proof_links=tuple(
            SliceProofLink(link.legacy_id, link.canonical_id)
            for link in snapshot.proof_links
        ),
        removal_decisions=tuple(decisions),
    )
    portability_evidence = StaticPortabilityEvidence(
        certificate=portability_certificate,
        ledger=portability_ledger,
    )
    return build_static_certificate_with_evidence(
        slice_evidence,
        portability_evidence,
        binding,
        schema_version=schema_version,
    )


__all__ = [
    "CertificateBridgeError",
    "StaticCertificateEvidence",
    "binding_from_manifest",
    "build_static_certificate_from_report",
    "build_static_certificate_with_evidence",
]
