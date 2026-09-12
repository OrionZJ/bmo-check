"""最终 verdict 入口；其他分析层只能提供事实或 Unknown。"""

from .verifier import explain_certificate, verify_certificate_scope, verify_portability
from .evidence import StaticPortabilityEvidence, verify_portability_with_evidence
from .certificate_bridge import (
    CertificateBridgeError,
    StaticCertificateEvidence,
    binding_from_manifest,
    build_static_certificate_from_report,
    build_static_certificate_with_evidence,
)
from .characterization import (
    FixedExecutionResult as StaticFixedExecutionResult,
    FixedModelResult as StaticFixedModelResult,
    check_fixed_execution as characterize_fixed_execution,
)

__all__ = [
    "StaticPortabilityEvidence",
    "StaticCertificateEvidence",
    "CertificateBridgeError",
    "binding_from_manifest",
    "build_static_certificate_from_report",
    "build_static_certificate_with_evidence",
    "StaticFixedExecutionResult",
    "StaticFixedModelResult",
    "characterize_fixed_execution",
    "explain_certificate",
    "verify_certificate_scope",
    "verify_portability",
    "verify_portability_with_evidence",
]
