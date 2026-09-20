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
    CertificateCompleteness,
    CertificateVerdict,
    CompletenessState,
    CompletenessStatus,
    EvidenceLedger,
    EvidenceId,
    EventDisposition,
    EventUniverseEntry,
    EventUniverseLedger,
    MemoryEventId,
    ObservedFact,
    DiagnosticHint,
    ProjectionLedger,
    ProjectionError,
    ObligationInventory,
    build_conflict_obligation_inventory,
    StaticCertificate,
    StaticVerification,
    UnknownFact as CanonicalUnknownFact,
    ProofFact,
    RemovalDecision,
    UnknownDischarge,
    verify_projection_ledger,
    build_projection_relation_obligation_inventory,
    digest_event_universe,
    digest_obligation_inventory,
    digest_projection_ledger,
    digest_unknown_ids,
    verify_static_certificate,
    verify_static_certificate_v2,
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
from ..slicing import build_projection_ledger, build_shared_memory_slice
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
    # obligation_inventory 是 checker 命题全集；v2 缺失时不能伪造空列表。
    obligation_inventory: ObligationInventory | None = None
    # event_universe 是静态输入事件的完整性账本；缺失时不能补成空集合。
    event_universe: EventUniverseLedger | None = None
    # projection_ledger 供后续 preservation replay 使用；不绕过当前 schema gate。
    projection_ledger: ProjectionLedger | None = None
    # projection_obligations 与 relation ledger 使用同一 proposition identity。
    projection_obligations: ObligationInventory | None = None


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


def _removed_event_ids_for_report(report: ProgramSliceReport) -> tuple[str, ...]:
    """Collect every event removed before the certificate boundary.

    The shared-state pass records its removals explicitly.  A later projection,
    such as application scope, can remove additional events and records those
    removals only in the final slice proof objects.  Dropping that second set
    would make the certificate's event universe disagree with the proof ledger.
    """

    removed: list[str] = []
    if report.shared_state is not None:
        removed.extend(report.shared_state.removed_event_ids)
    if report.shared_slice is not None:
        removed.extend(
            event_id
            for proof in report.shared_slice.proof_objects
            for event_id in proof.event_ids
        )
    return tuple(dict.fromkeys(removed))


def _build_event_universe_for_report(
    report: ProgramSliceReport,
    snapshot: object,
    ledger: EvidenceLedger,
    decisions: tuple[RemovalDecision, ...],
    *,
    scope: str,
) -> EventUniverseLedger:
    """把旧 report 的事件入口逐项对账为 v2 event universe。

    没有完整 memory-event 输入或无法唯一绑定 Unknown 时保留缺口。这里不
    用 ``shared_slice.events`` 的数量推断输入已经闭合。
    """

    event_ids = tuple(snapshot.event_ids)  # type: ignore[attr-defined]
    removed = {item.event_id: item.proof_id for item in decisions}
    retained = (
        {event.id for event in report.shared_slice.events}
        if report.shared_slice is not None
        else set()
    )
    unknown_by_event: dict[MemoryEventId, set[EvidenceId]] = {}
    for node in ledger.nodes():
        if isinstance(node, CanonicalUnknownFact) and isinstance(node.subject, MemoryEventId):
            unknown_by_event.setdefault(node.subject, set()).add(node.id)

    links = tuple(snapshot.event_links)  # type: ignore[attr-defined]
    entries: list[EventUniverseEntry] = []
    reasons: set[str] = set()
    if report.memory_events is None:
        reasons.add("memory-event input report is missing")
    for canonical_id in event_ids:
        legacy_ids = tuple(
            link.legacy_id for link in links if link.canonical_id == canonical_id
        )
        legacy_id = legacy_ids[0] if legacy_ids else None
        if canonical_id in removed:
            entries.append(
                EventUniverseEntry(
                    canonical_id,
                    EventDisposition.REMOVED_WITH_PROOF,
                    proof_ids=(removed[canonical_id],),
                )
            )
        elif canonical_id in unknown_by_event:
            entries.append(
                EventUniverseEntry(
                    canonical_id,
                    EventDisposition.UNRESOLVED,
                    unknown_ids=tuple(
                        sorted(unknown_by_event[canonical_id], key=lambda item: item.value)
                    ),
                )
            )
        elif legacy_id is not None and legacy_id in retained:
            entries.append(EventUniverseEntry(canonical_id, EventDisposition.RETAINED))
        else:
            reasons.add(f"event {canonical_id.value!r} has no unique disposition")

    completeness = (
        CompletenessState(CompletenessStatus.COMPLETE, scope)
        if not reasons
        else CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="; ".join(sorted(reasons)),
        )
    )
    return EventUniverseLedger(
        stage=scope,
        input_event_ids=event_ids,
        entries=tuple(entries),
        completeness=completeness,
    )


def _build_conflict_obligations_for_report(
    report: ProgramSliceReport,
    event_universe: EventUniverseLedger,
    ledger: EvidenceLedger,
    snapshot: object,
    *,
    scope: str,
) -> ObligationInventory:
    """为现有 conflict 候选建立 sidecar；候选边界不完整时显式标记。"""

    legacy_to_canonical = {
        link.legacy_id: link.canonical_id
        for link in snapshot.event_links  # type: ignore[attr-defined]
        if isinstance(link.canonical_id, MemoryEventId)
    }
    pairs: list[tuple[MemoryEventId, MemoryEventId]] = []
    issues: list[str] = []
    shared_slice = report.shared_slice
    if report.memory_events is None or shared_slice is None:
        issues.append("static conflict input is missing")
    if event_universe.completeness.status is not CompletenessStatus.COMPLETE:
        issues.append("event universe is incomplete")
    for candidate in shared_slice.conflicts if shared_slice is not None else ():
        first = legacy_to_canonical.get(candidate.first_event)
        second = legacy_to_canonical.get(candidate.second_event)
        if first is None or second is None:
            issues.append("conflict candidate has no canonical event identity")
            continue
        pairs.append((first, second))
    if ledger.unresolved_unknowns(scope):
        issues.append("static Unknown facts remain unresolved")
    candidate_state = (
        CompletenessState(CompletenessStatus.COMPLETE, scope)
        if not issues
        else CompletenessState(
            CompletenessStatus.INCOMPLETE,
            scope,
            reason="; ".join(sorted(set(issues))),
        )
    )
    return build_conflict_obligation_inventory(
        pairs,
        event_universe=event_universe,
        candidate_completeness=candidate_state,
        scope=scope,
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
    projection_ledger = slice_evidence.projection_ledger
    projection_obligations = slice_evidence.projection_obligations
    if (
        schema_version == "static-certificate-v2"
        and projection_ledger is None
        and verdict is CertificateVerdict.UNKNOWN
    ):
        # UNKNOWN 也要绑定一个明确的失败 sidecar；不能用 None 让 v2
        # verifier 把“没有投影输入”误解为空 relation universe。
        projection_ledger = ProjectionLedger(
            stage=binding.scope,
            input_relation_ids=(),
            entries=(),
            preservation_rule=None,
            completeness=CompletenessState(
                CompletenessStatus.INCOMPLETE,
                binding.scope,
                reason="static projection input is unavailable",
            ),
        )
        projection_obligations = build_projection_relation_obligation_inventory(
            projection_ledger,
            scope=binding.scope,
        )
    if projection_ledger is not None:
        try:
            verify_projection_ledger(
                projection_ledger,
                ledger,
                expected_scope=binding.scope,
            )
        except ProjectionError as error:
            # UNKNOWN 可以携带未闭合账本供诊断；确定性 verdict 不能把
            # 不完整 relation universe 当成 projection proof。
            if verdict is not CertificateVerdict.UNKNOWN:
                raise CertificateBridgeError(
                    f"canonical static projection replay failed: {error}"
                ) from error
        expected_obligations = build_projection_relation_obligation_inventory(
            projection_ledger,
            scope=binding.scope,
        )
        if projection_obligations is None:
            if verdict is not CertificateVerdict.UNKNOWN:
                raise CertificateBridgeError(
                    "projection relation obligations are missing"
                )
        elif projection_obligations != expected_obligations:
            raise CertificateBridgeError(
                "projection relation obligations do not match the relation ledger"
            )
        event_universe = slice_evidence.event_universe
        if event_universe is None and verdict is not CertificateVerdict.UNKNOWN:
            raise CertificateBridgeError("projection event universe is missing")
        if (
            event_universe is not None
            and event_universe.completeness.status is not CompletenessStatus.COMPLETE
            and verdict is not CertificateVerdict.UNKNOWN
        ):
            raise CertificateBridgeError("projection event universe is incomplete")
    completeness: CertificateCompleteness | None = None
    if schema_version == "static-certificate-v2":
        event_universe = slice_evidence.event_universe
        obligation_inventory = portability_evidence.obligation_inventory
        if event_universe is None:
            raise CertificateBridgeError(
                "static-certificate-v2 requires an event universe"
            )
        if obligation_inventory is None:
            raise CertificateBridgeError(
                "static-certificate-v2 requires an obligation inventory"
            )
        if projection_ledger is None or projection_obligations is None:
            raise CertificateBridgeError(
                "static-certificate-v2 requires projection ledgers"
            )
        if obligation_inventory.scope != binding.scope:
            raise CertificateBridgeError(
                "static obligation inventory scope does not match certificate"
            )
        completeness = CertificateCompleteness(
            event_universe_sha256=digest_event_universe(event_universe),
            obligation_sha256=digest_obligation_inventory(obligation_inventory),
            unknown_sha256=digest_unknown_ids(binding.scope, unknown_ids),
            projection_sha256=digest_projection_ledger(projection_ledger),
        )
    certificate = StaticCertificate(
        schema_version=schema_version,
        verdict=verdict,
        binding=binding,
        proof_roots=slice_evidence.proof_ids,
        removal_decisions=slice_evidence.removal_decisions,
        relevant_unknowns=unknown_ids,
        bounded=portability_evidence.certificate.checker.bounded,
        completeness=completeness,
    )
    try:
        if schema_version == "static-certificate-v2":
            assert completeness is not None
            assert slice_evidence.event_universe is not None
            assert portability_evidence.obligation_inventory is not None
            assert projection_ledger is not None
            assert projection_obligations is not None
            verification = verify_static_certificate_v2(
                certificate,
                ledger,
                event_universe=slice_evidence.event_universe,
                obligation_inventory=portability_evidence.obligation_inventory,
                projection_ledger=projection_ledger,
                projection_obligations=projection_obligations,
                expected_binding=binding,
            )
        else:
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
        obligation_inventory=portability_evidence.obligation_inventory,
        event_universe=slice_evidence.event_universe,
        projection_ledger=projection_ledger,
        projection_obligations=projection_obligations,
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
    removed_event_ids = _removed_event_ids_for_report(report)
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

    projection_ledger: ProjectionLedger | None = None
    projection_obligations: ObligationInventory | None = None
    if (
        report.memory_events is not None
        and report.shared_state is not None
        and report.shared_slice is not None
        and report.recovery.thread_roles is not None
    ):
        source_slice = build_shared_memory_slice(
            report.memory_events,
            report.shared_state,
            report.recovery.thread_roles,
        )
        event_identities = {
            link.legacy_id: link.canonical_id
            for link in snapshot.event_links
            if isinstance(link.canonical_id, MemoryEventId)
        }
        try:
            projection_ledger = build_projection_ledger(
                source_slice,
                report.shared_slice,
                event_identities=event_identities,
                scope=binding.scope,
            )
        except ValueError as error:
            raise CertificateBridgeError(
                f"static projection relation replay failed: {error}"
            ) from error
        projection_obligations = build_projection_relation_obligation_inventory(
            projection_ledger,
            scope=binding.scope,
        )

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

    merged_report_ledger = _merge_ledgers(proof_ledger, portability_ledger)
    event_universe = _build_event_universe_for_report(
        report,
        snapshot,
        merged_report_ledger,
        tuple(decisions),
        scope=binding.scope,
    )
    obligation_inventory = _build_conflict_obligations_for_report(
        report,
        event_universe,
        merged_report_ledger,
        snapshot,
        scope=binding.scope,
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
        event_universe=event_universe,
        projection_ledger=projection_ledger,
        projection_obligations=projection_obligations,
    )
    portability_evidence = StaticPortabilityEvidence(
        certificate=portability_certificate,
        ledger=portability_ledger,
        obligation_inventory=obligation_inventory,
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
