"""Backend-independent data models used by every analysis layer."""

from .binary import (
    ElfMetadata,
    ExecutionScope,
    FingerprintReport,
    ModuleFingerprint,
    ModuleRole,
    ProgramManifest,
)
from .certificate import CertificateScope
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
from .recovery import ProgramRecoveryReport
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
from .verdict import Verdict

__all__ = [
    "AbstractAddress",
    "AddressKind",
    "AnalysisCoverage",
    "BasicBlockFact",
    "CallKind",
    "CallSite",
    "CFGCoverage",
    "CertificateScope",
    "CodeLocation",
    "ControlFlowKind",
    "ControlFlowReport",
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
    "MemoryOperandFact",
    "ModuleFingerprint",
    "ModuleRole",
    "Ordering",
    "ProgramManifest",
    "ProgramRecoveryReport",
    "RelocationFact",
    "SynchronizationKind",
    "SynchronizationReport",
    "SynchronizationSummary",
    "SyncInstructionEvidence",
    "StrictModel",
    "ThreadCreateFact",
    "ThreadDiscoveryReport",
    "ThreadJoinFact",
    "ThreadRole",
    "UnknownFact",
    "UnknownKind",
    "Verdict",
]
