"""E2.5 litmus corpus/oracle 的 evaluation-only 边界。

这里描述测试输入和外部 oracle，不提供 MemoryEvent 或 verdict 构造函数。
Static、dynamic 和 core 都不能反向依赖这个包。
"""

from .model import (
    BinaryBinding,
    CoherencePair,
    CriticalEvent,
    ExecutionAssignment,
    FixtureEventKind,
    FromReadEdge,
    HerdOutcome,
    HerdOracleRecord,
    LitmusCase,
    LitmusFixtureError,
    LitmusManifest,
    ProgramOrderEdge,
    ReadFromChoice,
    RelationKind,
    load_manifest,
)
from .differential import (
    DifferentialComparison,
    DifferentialClassification,
    DifferentialStatus,
    compare_fixed_execution,
)
from .herd import (
    HerdInvocation,
    HerdOracleRequest,
    HerdOracleRun,
    HerdReplayResult,
    HerdReplayStatus,
    HerdRunStatus,
    parse_herd_outcome,
    replay_herd_oracle,
    run_herd_oracle,
)
from .oracle import (
    ORACLE_REPORT_SCHEMA,
    OracleToolError,
    oracle_record_from_run,
    replay_report,
    report_payload,
    write_report,
)
from .oracle_comparison import (
    OracleComparisonStatus,
    OracleLegalityComparison,
    compare_execution_with_oracle,
)
from .projection import CriticalProjectionError, project_critical_slice

__all__ = [
    "BinaryBinding",
    "CoherencePair",
    "CriticalEvent",
    "ExecutionAssignment",
    "FixtureEventKind",
    "FromReadEdge",
    "HerdOutcome",
    "HerdOracleRecord",
    "LitmusCase",
    "LitmusFixtureError",
    "LitmusManifest",
    "ProgramOrderEdge",
    "ReadFromChoice",
    "RelationKind",
    "load_manifest",
    "DifferentialComparison",
    "DifferentialClassification",
    "DifferentialStatus",
    "compare_fixed_execution",
    "HerdInvocation",
    "HerdOracleRequest",
    "HerdOracleRun",
    "HerdReplayResult",
    "HerdReplayStatus",
    "HerdRunStatus",
    "parse_herd_outcome",
    "replay_herd_oracle",
    "run_herd_oracle",
    "ORACLE_REPORT_SCHEMA",
    "OracleToolError",
    "oracle_record_from_run",
    "replay_report",
    "report_payload",
    "write_report",
    "OracleComparisonStatus",
    "OracleLegalityComparison",
    "compare_execution_with_oracle",
    "CriticalProjectionError",
    "project_critical_slice",
]
