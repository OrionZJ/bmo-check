"""最终 verdict 入口；其他分析层只能提供事实或 Unknown。"""

from .verifier import explain_certificate, verify_certificate_scope, verify_portability

__all__ = [
    "explain_certificate",
    "verify_certificate_scope",
    "verify_portability",
]
