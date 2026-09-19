from __future__ import annotations

import re
from enum import StrEnum

from bmo_check_core import TraceId
from pydantic import model_validator

from .manifest import StrictModel


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class CoverageState(StrEnum):
    """通信/窗口阶段是否把声明的输入全集完整交给下一阶段。"""

    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    RESOURCE_LIMITED = "RESOURCE_LIMITED"
    UNSUPPORTED = "UNSUPPORTED"


def _digest(name: str, value: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


class CommunicationCoverage(StrictModel):
    """communication scan 的事件全集、候选边和 scoped 输出对账。"""

    input_event_count: int
    input_event_sha256: str
    candidate_edge_count: int
    scoped_edge_count: int
    scoped_edge_sha256: str
    external_edge_count: int = 0
    state: CoverageState
    reason: str | None = None

    @model_validator(mode="after")
    def validate_coverage(self) -> "CommunicationCoverage":
        if any(
            value < 0
            for value in (
                self.input_event_count,
                self.candidate_edge_count,
                self.scoped_edge_count,
                self.external_edge_count,
            )
        ):
            raise ValueError("communication coverage counts cannot be negative")
        _digest("input event digest", self.input_event_sha256)
        _digest("scoped edge digest", self.scoped_edge_sha256)
        if self.scoped_edge_count > self.candidate_edge_count:
            raise ValueError("scoped edges cannot exceed candidate edges")
        if self.state is CoverageState.COMPLETE and self.reason is not None:
            raise ValueError("complete communication coverage cannot carry a reason")
        if self.state is not CoverageState.COMPLETE and not self.reason:
            raise ValueError("incomplete communication coverage requires a reason")
        return self


class WindowCoverage(StrictModel):
    """窗口分区的边输入全集与已归属窗口输出对账。"""

    input_edge_count: int
    input_edge_sha256: str
    assigned_edge_count: int
    assigned_edge_sha256: str
    window_count: int
    window_event_count: int
    state: CoverageState
    reason: str | None = None

    @model_validator(mode="after")
    def validate_coverage(self) -> "WindowCoverage":
        if any(
            value < 0
            for value in (
                self.input_edge_count,
                self.assigned_edge_count,
                self.window_count,
                self.window_event_count,
            )
        ):
            raise ValueError("window coverage counts cannot be negative")
        _digest("input edge digest", self.input_edge_sha256)
        _digest("assigned edge digest", self.assigned_edge_sha256)
        if self.assigned_edge_count > self.input_edge_count:
            raise ValueError("assigned edges cannot exceed input edges")
        if self.state is CoverageState.COMPLETE and self.reason is not None:
            raise ValueError("complete window coverage cannot carry a reason")
        if self.state is not CoverageState.COMPLETE and not self.reason:
            raise ValueError("incomplete window coverage requires a reason")
        return self


class TraceCoverage(StrictModel):
    """绑定 trace import subject 的通信和窗口 coverage ledger。"""

    trace_subject: str
    trace_sha256: str
    event_count: int
    event_sha256: str
    communication: CommunicationCoverage
    windows: WindowCoverage

    @model_validator(mode="after")
    def validate_identity(self) -> "TraceCoverage":
        try:
            TraceId.from_value(self.trace_subject)
        except (TypeError, ValueError) as error:
            raise ValueError("trace_subject must be a TraceId") from error
        _digest("trace digest", self.trace_sha256)
        _digest("event digest", self.event_sha256)
        if self.event_count < 0:
            raise ValueError("event_count cannot be negative")
        if self.communication.input_event_count != self.event_count:
            raise ValueError("communication input must equal trace event universe")
        if self.communication.input_event_sha256 != self.event_sha256:
            raise ValueError("communication input digest must equal trace event digest")
        if self.windows.input_edge_count != self.communication.scoped_edge_count:
            raise ValueError("window input must equal scoped communication output")
        if self.windows.input_edge_sha256 != self.communication.scoped_edge_sha256:
            raise ValueError("window input digest must equal scoped edge digest")
        return self


__all__ = [
    "CommunicationCoverage",
    "CoverageState",
    "TraceCoverage",
    "WindowCoverage",
]
