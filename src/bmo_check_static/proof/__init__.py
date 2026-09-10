"""最终 verdict 入口；其他分析层只能提供事实或 Unknown。"""

from .verifier import explain_certificate, verify_certificate_scope, verify_portability
from .evidence import StaticPortabilityEvidence, verify_portability_with_evidence

__all__ = [
    "StaticPortabilityEvidence",
    "explain_certificate",
    "verify_certificate_scope",
    "verify_portability",
    "verify_portability_with_evidence",
]
