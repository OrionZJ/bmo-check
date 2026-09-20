"""Static/trace certificate domain and proof-closure replay checks."""

from .model import (
    CertificateBinding,
    CertificateCompleteness,
    CertificateError,
    CertificateVerdict,
    RemovalDecision,
    StaticCertificate,
    TraceCertificate,
    TraceVerdict,
)
from .digests import (
    digest_event_universe,
    digest_obligation_inventory,
    digest_projection_ledger,
    digest_unknown_ids,
)
from .verification import (
    StaticVerification,
    TraceVerification,
    TypedDischargeVerification,
    UnknownPropositionAudit,
    audit_unknown_propositions,
    verify_typed_discharge,
    verify_static_certificate,
    verify_static_certificate_v2,
    verify_trace_certificate,
)

__all__ = [
    "CertificateBinding",
    "CertificateCompleteness",
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
    "verify_static_certificate_v2",
    "verify_trace_certificate",
    "digest_event_universe",
    "digest_obligation_inventory",
    "digest_projection_ledger",
    "digest_unknown_ids",
]
