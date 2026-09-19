"""Static/trace certificate domain and proof-closure replay checks."""

from .model import (
    CertificateBinding,
    CertificateError,
    CertificateVerdict,
    RemovalDecision,
    StaticCertificate,
    TraceCertificate,
    TraceVerdict,
)
from .verification import (
    StaticVerification,
    TraceVerification,
    TypedDischargeVerification,
    UnknownPropositionAudit,
    audit_unknown_propositions,
    verify_typed_discharge,
    verify_static_certificate,
    verify_trace_certificate,
)

__all__ = [
    "CertificateBinding",
    "CertificateError",
    "CertificateVerdict",
    "RemovalDecision",
    "StaticCertificate",
    "StaticVerification",
    "TraceCertificate",
    "TraceVerification",
    "TypedDischargeVerification",
    "UnknownPropositionAudit",
    "audit_unknown_propositions",
    "verify_typed_discharge",
    "TraceVerdict",
    "verify_static_certificate",
    "verify_trace_certificate",
]
