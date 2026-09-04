from bmo_check_dynamic.model import EventKind, TraceEvent
from bmo_check_dynamic.normalize import ObjectTracker


def test_reused_address_gets_new_generation() -> None:
    tracker = ObjectTracker()
    first = tracker.observe(TraceEvent(1, 1, 1, 0, EventKind.ALLOC, 0x1000, 64))
    tracker.observe(TraceEvent(1, 2, 2, 0, EventKind.FREE, 0x1000))
    second = tracker.observe(TraceEvent(1, 3, 3, 0, EventKind.ALLOC, 0x1000, 64))
    assert first is not None and second is not None
    assert first.object_id != second.object_id
    assert second.generation == first.generation + 1
