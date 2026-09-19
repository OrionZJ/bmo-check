from __future__ import annotations

import pytest

from bmo_check_core import ModuleId, TraceId
from bmo_check_dynamic.model import (
    CommunicationCoverage,
    CoverageState,
    TraceCoverage,
    WindowCoverage,
)


HASH = "a" * 64


def _coverage() -> TraceCoverage:
    module = ModuleId.from_parts(HASH, "executable")
    trace = TraceId.from_parts("1.2", HASH, (module,), ("complete",), "b" * 64)
    communication = CommunicationCoverage(
        input_event_count=4,
        input_event_sha256=HASH,
        candidate_edge_count=2,
        scoped_edge_count=2,
        scoped_edge_sha256="b" * 64,
        state=CoverageState.COMPLETE,
    )
    windows = WindowCoverage(
        input_edge_count=2,
        input_edge_sha256="b" * 64,
        assigned_edge_count=2,
        assigned_edge_sha256="c" * 64,
        window_count=1,
        window_event_count=4,
        state=CoverageState.COMPLETE,
    )
    return TraceCoverage(
        trace_subject=trace.value,
        trace_sha256="d" * 64,
        event_count=4,
        event_sha256=HASH,
        communication=communication,
        windows=windows,
    )


def test_coverage_binds_event_and_edge_universes() -> None:
    coverage = _coverage()

    assert coverage.communication.state is CoverageState.COMPLETE
    assert coverage.windows.input_edge_count == 2


def test_missing_or_mismatched_coverage_cannot_be_complete() -> None:
    with pytest.raises(ValueError, match="communication input"):
        TraceCoverage(
            trace_subject=_coverage().trace_subject,
            trace_sha256="d" * 64,
            event_count=5,
            event_sha256=HASH,
            communication=_coverage().communication,
            windows=_coverage().windows,
        )

    with pytest.raises(ValueError, match="requires a reason"):
        CommunicationCoverage(
            input_event_count=1,
            input_event_sha256=HASH,
            candidate_edge_count=0,
            scoped_edge_count=0,
            scoped_edge_sha256=HASH,
            state=CoverageState.INCOMPLETE,
        )

