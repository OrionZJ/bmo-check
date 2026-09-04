from pathlib import Path

from bmo_check_dynamic.analysis import locate_instruction_site
from bmo_check_dynamic.model import EventFlags, EventKind, TraceEvent
from bmo_check_dynamic.trace import TraceWriter


def test_locate_site_groups_hits_without_loading_trace(tmp_path: Path) -> None:
    trace_dir = tmp_path / "trace"
    trace_dir.mkdir()
    module = "/lib/libexample.so"
    (trace_dir / "modules.tsv").write_text(
        f"0x1000\t0x2000\t{module}\n", encoding="utf-8"
    )
    with TraceWriter(trace_dir / "events-1.bin") as writer:
        writer.write(TraceEvent(1, 1, 1, 0x1010, EventKind.STORE, 0x4000, 4))
        writer.write(TraceEvent(1, 5, 5, 0x1010, EventKind.STORE, 0x4004, 4))
        writer.write(
            TraceEvent(
                2,
                3,
                3,
                0x1010,
                EventKind.ATOMIC_RMW,
                0x4008,
                4,
                flags=EventFlags.LOCK_PREFIX,
            )
        )
        writer.write(TraceEvent(2, 4, 4, 0x1020, EventKind.LOAD, 0x5000, 8))

    evidence = locate_instruction_site(trace_dir, module, 0x10)

    assert evidence.event_count == 3
    assert evidence.thread_event_counts == ((1, 2), (2, 1))
    assert evidence.thread_sequence_bounds == ((1, 1, 5), (2, 3, 3))
    assert evidence.kind_counts == (("ATOMIC_RMW", 1), ("STORE", 2))
    assert evidence.size_counts == ((4, 3),)
    assert evidence.flag_counts == ((0, 2), (2, 1))
