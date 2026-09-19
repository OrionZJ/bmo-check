from __future__ import annotations

from pydantic import Field

from .certificate import StrictModel, TraceVerdict


class CampaignMember(StrictModel):
    """一次独立 capture/analyze 成员的可审计摘要。"""

    name: str
    iteration: int
    trace_directory: str
    certificate_path: str | None = None
    verdict: TraceVerdict = TraceVerdict.UNKNOWN
    trace_id: str | None = None
    trace_sha256: str | None = None
    event_count: int = 0
    unique_pc_count: int = 0
    trace_bytes: int = 0
    capture_seconds: float = 0.0
    analysis_seconds: float = 0.0
    replay_seconds: float = 0.0
    max_rss_kb: int | None = None
    resource_limited: bool = False
    dedup_key: str | None = None
    duplicate_of: str | None = None
    error: str | None = None


class CampaignSummary(StrictModel):
    """campaign 级结论；不能因去重或失败成员缺席而升格。"""

    schema_version: str = "campaign-v2"
    verdict: TraceVerdict
    trace_count: int
    member_count: int
    verdict_counts: dict[str, int]
    unique_trace_count: int
    duplicate_trace_count: int
    total_events: int
    total_unique_pcs_per_trace: int
    total_trace_bytes: int
    unique_trace_bytes: int
    resource_limited_count: int = 0
    certificates: tuple[CampaignMember, ...] = Field(default_factory=tuple)
    limitation: str = "campaign verdict covers only the listed trace certificates"
