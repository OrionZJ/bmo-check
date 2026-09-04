from __future__ import annotations

from enum import Enum

from pydantic import Field, model_validator

from .manifest import BinaryFingerprint, StrictModel


class TraceVerdict(str, Enum):
    # TRACE_SAFE 只覆盖证书绑定的事件骨架，不能外推到其他输入或路径。
    TRACE_SAFE = "TRACE_SAFE"
    COUNTEREXAMPLE = "COUNTEREXAMPLE"
    UNKNOWN = "UNKNOWN"


class TraceScope(StrictModel):
    trace_ids: tuple[str, ...]
    trace_sha256: tuple[str, ...]
    executable: BinaryFingerprint
    libraries: tuple[BinaryFingerprint, ...] = ()
    commands: tuple[tuple[str, ...], ...]
    working_directories: tuple[str, ...]
    limitation: str = (
        "结论只覆盖已记录的线程内事件、实际地址和控制流骨架；"
        "不覆盖未执行路径、其他输入或未来调度。"
    )


class CandidateWitness(StrictModel):
    window_id: str
    read_from: tuple[tuple[str, str | None], ...] = ()
    coherence: tuple[tuple[str, str], ...] = ()
    source_cycle: tuple[str, ...] = ()
    validated: bool = False
    reason: str


class WindowResult(StrictModel):
    window_id: str
    event_ids: tuple[str, ...]
    examined_executions: int = 0
    status: str
    reason: str
    witness: CandidateWitness | None = None


class DynamicCertificate(StrictModel):
    schema_version: str = "1.0"
    verdict: TraceVerdict
    scope: TraceScope
    dbt_contract_sha256: str
    analyzer_version: str
    trace_complete: bool
    event_count: int
    thread_count: int
    object_count: int
    unique_pc_count: int
    communication_edge_count: int
    indirect_target_count: int
    windows: tuple[WindowResult, ...] = ()
    unknown_reasons: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()

    @model_validator(mode="after")
    def keep_verdict_strict(self) -> "DynamicCertificate":
        if self.verdict == TraceVerdict.TRACE_SAFE:
            if not self.trace_complete or self.unknown_reasons:
                raise ValueError("TRACE_SAFE requires a complete trace without Unknowns")
            if any(window.status != "safe" for window in self.windows):
                raise ValueError("TRACE_SAFE requires every window to be safe")
        if self.verdict == TraceVerdict.COUNTEREXAMPLE:
            if not any(
                window.witness is not None and window.witness.validated
                for window in self.windows
            ):
                raise ValueError("COUNTEREXAMPLE requires a validated witness")
        return self
