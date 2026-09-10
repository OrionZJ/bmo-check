"""把旧静态 verdict 接到 canonical static certificate。

旧 portability checker 仍是事实和 verdict 的来源；本模块只在证书边界
把已经生成的 typed sidecar 组装起来，并立即 replay。这样迁移期间不会
出现一份没有 proof closure 的“新 SAFE”证书。
"""

from __future__ import annotations

from dataclasses import dataclass

from bmo_check_core import (
    BinaryClosureId,
    CertificateBinding,
    CertificateError,
    CertificateVerdict,
    EvidenceLedger,
    ObservedFact,
    DiagnosticHint,
    StaticCertificate,
    StaticVerification,
    UnknownFact as CanonicalUnknownFact,
    ProofFact,
    verify_static_certificate,
)
from bmo_check_static.model import ModuleRole, ProgramManifest, Verdict

from ..slicing.evidence import StaticSliceEvidence
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


__all__ = [
    "CertificateBridgeError",
    "StaticCertificateEvidence",
    "binding_from_manifest",
    "build_static_certificate_with_evidence",
]
