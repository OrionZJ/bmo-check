"""Backend-independent data models used by every analysis layer."""

from .binary import (
    ElfMetadata,
    ExecutionScope,
    FingerprintReport,
    ModuleFingerprint,
    ModuleRole,
    ProgramManifest,
)
from .certificate import (
    CertificateCoverage,
    CertificateModule,
    CertificateScope,
    PortabilityCertificate,
)
from .common import StrictModel
from .controlflow import (
    BasicBlockFact,
    CallKind,
    CallSite,
    CFGCoverage,
    CodeLocation,
    ControlFlowReport,
    FunctionFact,
    IndirectSiteFact,
    IndirectTargetSet,
)
from .coverage import AnalysisCoverage
from .instruction import (
    ControlFlowKind,
    FenceKind,
    InstructionFact,
    InstructionModuleFacts,
    MemoryAccessKind,
    MemoryOperandFact,
)
from .memory_event import AbstractAddress, AddressKind, EventKind, MemoryEvent
from .memory_event import MemoryEventReport, ProgramOrderEdge
from .recovery import ProgramRecoveryReport
from .sharing import (
    AliasRelation,
    ConflictCandidate,
    EscapeKind,
    ProofObject,
    ProofReason,
    PruningCoverage,
    SharedMemorySlice,
    SharedObject,
    SharedStateReport,
    SharingClass,
    SynchronizationEdge,
)
from .slicing import ProgramSliceReport
from .symbol import FunctionSymbolFact, RelocationFact
from .sync import (
    Ordering,
    SynchronizationKind,
    SynchronizationReport,
    SynchronizationSummary,
    SyncInstructionEvidence,
)
from .thread import (
    ThreadCreateFact,
    ThreadDiscoveryReport,
    ThreadJoinFact,
    ThreadRole,
)
from .unknown import UnknownFact, UnknownKind
from .verdict import (
    CheckerConclusion,
    CheckerLimits,
    CheckerReport,
    CoherenceChoice,
    CounterexampleEvent,
    CounterexampleTrace,
    ReadFromChoice,
    Verdict,
)

__all__ = [
    "AbstractAddress",
    "AddressKind",
    "AnalysisCoverage",
    "BasicBlockFact",
    "CallKind",
    "CallSite",
    "CFGCoverage",
    "CertificateCoverage",
    "CertificateModule",
    "CertificateScope",
    "CheckerConclusion",
    "CheckerLimits",
    "CheckerReport",
    "CodeLocation",
    "ControlFlowKind",
    "ControlFlowReport",
    "CoherenceChoice",
    "CounterexampleEvent",
    "CounterexampleTrace",
    "ElfMetadata",
    "EventKind",
    "ExecutionScope",
    "FenceKind",
    "FingerprintReport",
    "FunctionFact",
    "FunctionSymbolFact",
    "IndirectSiteFact",
    "IndirectTargetSet",
    "InstructionFact",
    "InstructionModuleFacts",
    "MemoryAccessKind",
    "MemoryEvent",
    "MemoryEventReport",
    "MemoryOperandFact",
    "ModuleFingerprint",
    "ModuleRole",
    "Ordering",
    "ProgramManifest",
    "PortabilityCertificate",
    "ProgramRecoveryReport",
    "ProgramSliceReport",
    "ProgramOrderEdge",
    "ProofObject",
    "ProofReason",
    "PruningCoverage",
    "RelocationFact",
    "ReadFromChoice",
    "SynchronizationKind",
    "SynchronizationReport",
    "SynchronizationSummary",
    "SyncInstructionEvidence",
    "StrictModel",
    "SharedMemorySlice",
    "SharedObject",
    "SharedStateReport",
    "SharingClass",
    "EscapeKind",
    "AliasRelation",
    "ConflictCandidate",
    "SynchronizationEdge",
    "ThreadCreateFact",
    "ThreadDiscoveryReport",
    "ThreadJoinFact",
    "ThreadRole",
    "UnknownFact",
    "UnknownKind",
    "Verdict",
]
