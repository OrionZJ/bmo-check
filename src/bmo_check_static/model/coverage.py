from __future__ import annotations

from .common import StrictModel


class AnalysisCoverage(StrictModel):
    modules: int = 0
    functions: int = 0
    reachable_functions: int = 0
    indirect_sites: int = 0
    incomplete_indirect_sites: int = 0
    thread_roles: int = 0
    unknown_thread_entries: int = 0
    instructions: int = 0
    memory_instructions: int = 0
    unknown_instruction_facts: int = 0
    memory_events: int = 0
    shared_events: int = 0
    unknown_shared_effects: int = 0
