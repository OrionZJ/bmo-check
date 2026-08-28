from __future__ import annotations

import hashlib
import json

from bmo_check.model import (
    CertificateCoverage,
    CertificateModule,
    CertificateScope,
    CheckerConclusion,
    CheckerLimits,
    CheckerReport,
    PortabilityCertificate,
    ProgramManifest,
    ProgramSliceReport,
    SharingClass,
    UnknownFact,
    UnknownKind,
    Verdict,
)

from .encoding import BACKEND_NAME, BACKEND_VERSION, check_finite_portability


def _deduplicate_unknowns(unknowns: list[UnknownFact]) -> tuple[UnknownFact, ...]:
    seen: set[tuple[object, ...]] = set()
    result: list[UnknownFact] = []
    for fact in unknowns:
        # details 常含派生 edge/event ID；根因相同不能膨胀成几十个 proof obligation。
        key = (
            fact.kind,
            fact.reason,
            fact.impact,
            fact.module,
            fact.pc,
            fact.function,
        )
        if key not in seen:
            seen.add(key)
            result.append(fact)
    return tuple(result)


def _collect_unknowns(report: ProgramSliceReport) -> tuple[UnknownFact, ...]:
    recovery = report.recovery
    unknowns = list(recovery.manifest.unknowns)
    unknowns.extend(recovery.unknowns)
    unknowns.extend(report.unknowns)
    if recovery.thread_roles is not None:
        for role in recovery.thread_roles.roles:
            if not role.complete:
                unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.UNKNOWN_THREAD_ENTRY,
                        reason="thread role does not have a closed entry set",
                        impact="worker memory events may be missing",
                        module=(role.create_site.module_path if role.create_site else None),
                        pc=(role.create_site.pc if role.create_site else None),
                        details={"thread_role": role.id},
                    )
                )
    if report.shared_slice is not None:
        removed_ids = {
            event_id
            for proof in report.shared_slice.proof_objects
            for event_id in proof.event_ids
        }
        explained_event_ids: set[str] = set()
        for fact in report.shared_slice.unknowns:
            event_id = fact.details.get("event_id")
            event_ids = fact.details.get("event_ids")
            if isinstance(event_id, str) and event_id in removed_ids:
                continue
            if (
                isinstance(event_ids, list)
                and event_ids
                and all(
                    isinstance(item, str) and item in removed_ids
                    for item in event_ids
                )
            ):
                continue
            unknowns.append(fact)
            if isinstance(event_id, str):
                explained_event_ids.add(event_id)
            if isinstance(event_ids, list):
                explained_event_ids.update(
                    item for item in event_ids if isinstance(item, str)
                )
        for event in report.shared_slice.events:
            if (
                event.kind.value in {"OpaqueCall", "Syscall", "UnknownMemoryEffect"}
                and event.id not in explained_event_ids
            ):
                # 提取阶段通常已给未知 effect 绑定根因。这里只为没有诊断的哨兵补缺，
                # 否则同一个 call 会同时变成“缺少摘要”和“OpaqueCall remains”。
                unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.UNKNOWN_MEMORY_EFFECT,
                        reason=f"{event.kind.value} remains in the shared-memory slice",
                        impact="the finite checker cannot close its shared-memory effects",
                        module=event.module,
                        pc=event.pc,
                        function=event.function,
                    )
                )
        for edge in report.shared_slice.synchronization:
            if not edge.complete:
                unknowns.append(
                    UnknownFact(
                        kind=UnknownKind.UNKNOWN_SYNCHRONIZATION,
                        reason=edge.reason or "synchronization edge is incomplete",
                        impact="ordering cannot cross this unresolved synchronization relation",
                        details={
                            "source_event": edge.source_event,
                            "target_event": edge.target_event,
                            "kind": edge.kind,
                        },
                    )
                )
    if not recovery.manifest.closure_complete and not recovery.manifest.unknowns:
        unknowns.append(
            UnknownFact(
                kind=UnknownKind.PORTABILITY_CHECK_INCOMPLETE,
                reason="binary dependency closure is not complete",
                impact="unseen code may add shared-memory communication",
            )
        )
    if recovery.manifest.dbt_revision is None:
        unknowns.append(
            UnknownFact(
                kind=UnknownKind.MISSING_DBT_REVISION,
                reason="the analyzed DBT revision is not recorded",
                impact="the certificate cannot bind the mo-off lowering implementation",
            )
        )
    if report.shared_slice is None:
        unknowns.append(
            UnknownFact(
                kind=UnknownKind.PORTABILITY_CHECK_INCOMPLETE,
                reason="shared-memory slice is unavailable",
                impact="the portability checker has no closed communication input",
            )
        )
    return _deduplicate_unknowns(unknowns)


def _analysis_config_sha256(
    manifest: ProgramManifest,
    limits: CheckerLimits,
    analysis_options: dict[str, object] | None = None,
) -> str:
    material = {
        "execution": manifest.execution.model_dump(mode="json"),
        "checker_limits": limits.model_dump(mode="json"),
        "analysis_options": analysis_options or {},
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _scope(
    manifest: ProgramManifest,
    limits: CheckerLimits,
    analysis_options: dict[str, object] | None = None,
) -> CertificateScope:
    executable = manifest.executable
    executable_hash = executable.sha256 if executable is not None else ""
    modules = []
    if executable is not None:
        modules.append(
            CertificateModule(
                path=executable.path,
                sha256=executable.sha256,
                role=executable.role.value,
            )
        )
    if manifest.interpreter is not None:
        modules.append(
            CertificateModule(
                path=manifest.interpreter.path,
                sha256=manifest.interpreter.sha256,
                role=manifest.interpreter.role.value,
            )
        )
    modules.extend(
        CertificateModule(path=module.path, sha256=module.sha256, role=module.role.value)
        for module in manifest.libraries
    )
    return CertificateScope(
        executable_sha256=executable_hash,
        library_sha256=tuple(module.sha256 for module in manifest.libraries),
        modules=tuple(modules),
        dbt_contract_version=manifest.dbt_contract_version,
        dbt_revision=manifest.dbt_revision or "",
        function_effect_contract_version=(
            manifest.function_effect_contract_version
        ),
        function_effect_contract_sha256=(
            manifest.function_effect_contract_sha256
        ),
        argv=manifest.execution.argv,
        thread_count_min=manifest.execution.thread_count_min,
        thread_count_max=manifest.execution.thread_count_max,
        analysis_config_sha256=_analysis_config_sha256(
            manifest, limits, analysis_options
        ),
    )


def _coverage(report: ProgramSliceReport) -> CertificateCoverage:
    recovery = report.recovery
    control_flow = recovery.control_flow
    thread_roles = recovery.thread_roles
    events = report.memory_events
    shared_state = report.shared_state
    shared_slice = report.shared_slice
    manifest = recovery.manifest
    modules = int(manifest.executable is not None) + int(manifest.interpreter is not None)
    modules += len(manifest.libraries)
    pruning_counts: dict[str, int] = {}
    if shared_state is not None:
        for proof in shared_state.proofs:
            pruning_counts[proof.reason.value] = (
                pruning_counts.get(proof.reason.value, 0) + len(proof.event_ids)
            )
    function_ids = (
        tuple(
            f"{function.location.module_sha256}:0x{function.location.pc:x}"
            for function in control_flow.functions
        )
        if control_flow is not None
        else ()
    )
    indirect_site_ids = (
        tuple(
            f"{site.location.module_sha256}:0x{site.location.pc:x}"
            for site in control_flow.indirect_sites
        )
        if control_flow is not None
        else ()
    )
    incomplete_indirect_site_ids = (
        tuple(
            f"{site.location.module_sha256}:0x{site.location.pc:x}"
            for site in control_flow.indirect_sites
            if not site.targets.complete
        )
        if control_flow is not None
        else ()
    )
    memory_event_ids = (
        tuple(event.id for event in events.events) if events is not None else ()
    )
    shared_event_ids = (
        tuple(event.id for event in shared_slice.events)
        if shared_slice is not None
        else ()
    )
    unknown_memory_effect_ids = (
        tuple(
            event.id
            for event in shared_slice.events
            if event.kind.value in {"OpaqueCall", "Syscall", "UnknownMemoryEffect"}
        )
        if shared_slice is not None
        else ()
    )
    shared_object_ids = (
        tuple(obj.id for obj in shared_state.objects)
        if shared_state is not None
        else ()
    )
    unknown_shared_object_ids = (
        tuple(
            obj.id
            for obj in shared_state.objects
            if obj.sharing == SharingClass.SHARED_UNKNOWN
        )
        if shared_state is not None
        else ()
    )
    return CertificateCoverage(
        modules=modules,
        functions=len(control_flow.functions) if control_flow is not None else 0,
        indirect_sites=len(control_flow.indirect_sites) if control_flow is not None else 0,
        incomplete_indirect_sites=(
            control_flow.coverage.incomplete_indirect_sites
            if control_flow is not None
            else 0
        ),
        function_ids=function_ids,
        indirect_site_ids=indirect_site_ids,
        incomplete_indirect_site_ids=incomplete_indirect_site_ids,
        thread_roles=len(thread_roles.roles) if thread_roles is not None else 0,
        unknown_thread_entries=(
            sum(
                fact.kind == UnknownKind.UNKNOWN_THREAD_ENTRY
                for fact in thread_roles.unknowns
            )
            if thread_roles is not None
            else 0
        ),
        thread_role_ids=(
            tuple(role.id for role in thread_roles.roles)
            if thread_roles is not None
            else ()
        ),
        memory_events=len(events.events) if events is not None else 0,
        shared_events=len(shared_slice.events) if shared_slice is not None else 0,
        unknown_memory_effects=(
            shared_slice.coverage.unknown_events if shared_slice is not None else 0
        ),
        memory_event_ids=memory_event_ids,
        shared_event_ids=shared_event_ids,
        unknown_memory_effect_ids=unknown_memory_effect_ids,
        shared_objects=len(shared_state.objects) if shared_state is not None else 0,
        unknown_shared_objects=(
            sum(obj.sharing == SharingClass.SHARED_UNKNOWN for obj in shared_state.objects)
            if shared_state is not None
            else 0
        ),
        shared_object_ids=shared_object_ids,
        unknown_shared_object_ids=unknown_shared_object_ids,
        pruning_counts=pruning_counts,
    )


def _checker_unknown(checker: CheckerReport) -> UnknownFact:
    if "timeout" in checker.reason:
        kind = UnknownKind.PORTABILITY_CHECK_TIMEOUT
    elif "max_executions" in checker.reason:
        kind = UnknownKind.PORTABILITY_CHECK_BOUND
    elif checker.unsupported_events:
        kind = UnknownKind.UNSUPPORTED_PORTABILITY_INPUT
    else:
        kind = UnknownKind.PORTABILITY_CHECK_INCOMPLETE
    return UnknownFact(
        kind=kind,
        reason=checker.reason,
        impact="mo-off cannot be approved from this finite portability run",
        details={
            "examined_executions": checker.examined_executions,
            "unsupported_events": list(checker.unsupported_events),
        },
    )


def verify_portability(
    report: ProgramSliceReport,
    limits: CheckerLimits | None = None,
    analysis_options: dict[str, object] | None = None,
) -> PortabilityCertificate:
    """这是唯一把分析事实映射为最终 verdict 的入口。"""

    limits = limits or CheckerLimits()
    manifest = report.recovery.manifest
    scope = _scope(manifest, limits, analysis_options)
    coverage = _coverage(report)
    unknowns = _collect_unknowns(report)
    proof_objects = (
        report.shared_slice.proof_objects if report.shared_slice is not None else ()
    )

    if unknowns:
        checker = CheckerReport(
            backend=BACKEND_NAME,
            backend_version=BACKEND_VERSION,
            limits=limits,
            conclusion=CheckerConclusion.INCOMPLETE,
            reason="relevant Unknown facts block the portability proof",
        )
        return PortabilityCertificate(
            verdict=Verdict.UNKNOWN,
            scope=scope,
            coverage=coverage,
            checker=checker,
            proof_objects=proof_objects,
            relevant_unknowns=unknowns,
        )

    shared_slice = report.shared_slice
    assert shared_slice is not None
    if not shared_slice.conflicts:
        checker = CheckerReport(
            backend=BACKEND_NAME,
            backend_version=BACKEND_VERSION,
            bounded=False,
            limits=limits,
            conclusion=CheckerConclusion.STRUCTURAL_SAFE,
            reason="all cross-thread conflicting events were removed by checked proof objects",
        )
        return PortabilityCertificate(
            verdict=Verdict.SAFE,
            scope=scope,
            coverage=coverage,
            checker=checker,
            proof_objects=proof_objects,
        )

    checker, counterexample = check_finite_portability(shared_slice, limits)
    if checker.conclusion == CheckerConclusion.TARGET_ONLY:
        assert counterexample is not None
        return PortabilityCertificate(
            verdict=Verdict.COUNTEREXAMPLE,
            scope=scope,
            coverage=coverage,
            checker=checker,
            proof_objects=proof_objects,
            counterexample=counterexample,
        )

    checker_unknown = _checker_unknown(checker)
    return PortabilityCertificate(
        verdict=Verdict.UNKNOWN,
        scope=scope,
        coverage=coverage,
        checker=checker,
        proof_objects=proof_objects,
        relevant_unknowns=(checker_unknown,),
    )


def verify_certificate_scope(
    certificate: PortabilityCertificate,
    manifest: ProgramManifest,
    limits: CheckerLimits,
    analysis_options: dict[str, object] | None = None,
) -> tuple[UnknownFact, ...]:
    """复用前重新计算 scope；任何差异都把证书降为 stale。"""

    expected = _scope(manifest, limits, analysis_options)
    if certificate.scope == expected:
        return ()
    return (
        UnknownFact(
            kind=UnknownKind.STALE_CERTIFICATE,
            reason="certificate scope does not match the current binary, DBT, execution, or checker configuration",
            impact="this certificate cannot authorize mo-off",
            details={
                "certificate_scope": certificate.scope.model_dump(mode="json"),
                "current_scope": expected.model_dump(mode="json"),
            },
        ),
    )


def explain_certificate(certificate: PortabilityCertificate) -> str:
    lines = [f"verdict: {certificate.verdict.value}"]
    lines.append(
        "scope: "
        f"exe={certificate.scope.executable_sha256[:12]} "
        f"libraries={len(certificate.scope.library_sha256)} "
        f"dbt={certificate.scope.dbt_revision[:12] or '<missing>'}"
    )
    lines.append(
        "coverage: "
        f"events={certificate.coverage.memory_events} "
        f"shared={certificate.coverage.shared_events} "
        f"unknown={len(certificate.relevant_unknowns)}"
    )
    lines.append(f"checker: {certificate.checker.reason}")

    proofs_by_reason: dict[str, list] = {}
    for proof in certificate.proof_objects:
        proofs_by_reason.setdefault(proof.reason.value, []).append(proof)
    for reason, proofs in sorted(proofs_by_reason.items()):
        removed = sum(len(proof.event_ids) for proof in proofs)
        lines.append(f"proof {reason}: {removed} events in {len(proofs)} proof objects")
        for proof in proofs[:3]:
            lines.append(f"  events: {', '.join(proof.event_ids[:4])}")
            for fact in proof.supporting_facts[:2]:
                lines.append(f"  because: {fact}")
        if len(proofs) > 3:
            lines.append(f"  ... {len(proofs) - 3} more proof objects")

    unknowns_by_kind: dict[str, list[UnknownFact]] = {}
    for unknown in certificate.relevant_unknowns:
        unknowns_by_kind.setdefault(unknown.kind.value, []).append(unknown)
    for kind, unknowns in sorted(unknowns_by_kind.items()):
        lines.append(f"unknown {kind}: {len(unknowns)} facts")
        for unknown in unknowns[:5]:
            location = ""
            if unknown.module:
                location += f" {unknown.module}"
            if unknown.pc is not None:
                location += f":0x{unknown.pc:x}"
            lines.append(f"  {location.strip() or '<global>'}: {unknown.reason}")
        if len(unknowns) > 5:
            lines.append(f"  ... {len(unknowns) - 5} more facts")

    if certificate.counterexample is not None:
        trace = certificate.counterexample
        lines.append("target-only execution:")
        for event in trace.events:
            lines.append(
                f"  {event.thread_role} 0x{event.pc:x} {event.kind.value} "
                f"object={event.object_id} "
                f"source={event.source_ordering.value} "
                f"target={event.target_ordering.value}"
            )
        for choice in trace.read_from:
            source = choice.store_event or "initial"
            lines.append(f"  rf: {source} -> {choice.load_event}")
        lines.append(f"  x86 cycle: {' -> '.join(trace.source_cycle)}")
        for missing in trace.missing_ordering:
            lines.append(f"  missing order: {missing}")
    return "\n".join(lines) + "\n"
