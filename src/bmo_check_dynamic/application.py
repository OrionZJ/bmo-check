"""dynamic capture/analyze 的应用服务边界。

CLI 负责解析参数和渲染 certificate；进程控制、trace 目录写入和离线分析
由这里调用既有 route service。这样后续 diagnose 可以消费只读 snapshot，
而不需要反向调用 CLI 或读取其 argparse 状态。
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from bmo_check_dynamic.capture import capture_program
from bmo_check_dynamic.config import DynamicConfig
from bmo_check_dynamic.analysis import WindowCharacterizationReport
from bmo_check_dynamic.model import (
    DynamicCertificate,
    SliceCandidateReport,
    SlicePlanReport,
    TraceManifest,
    TraceObligationBottleneckReport,
    TraceCycleRelevanceReport,
    TracePpoReductionCertificate,
    TracePpoReductionReport,
    TracePpoReductionReplayReport,
)
from bmo_check_dynamic.pipeline import (
    analyze_trace,
    candidate_slice_trace,
    characterize_trace,
    obligation_bottleneck_trace,
    cycle_relevance_trace,
    ppo_reduction_trace,
    ppo_replay_trace,
    slice_plan_trace,
)


class DynamicApplicationError(ValueError):
    """dynamic service 请求字段不满足边界时抛出。"""


@dataclass(frozen=True, slots=True)
class CaptureRequest:
    command: tuple[str, ...]
    output_dir: Path
    dynamorio_home: Path
    client_path: Path
    environment: tuple[tuple[str, str], ...] = ()
    working_directory: Path | None = None
    max_thread_events: int | None = None

    def __post_init__(self) -> None:
        if not self.command:
            raise DynamicApplicationError("capture command cannot be empty")
        for name in ("output_dir", "dynamorio_home", "client_path"):
            if not isinstance(getattr(self, name), Path):
                raise DynamicApplicationError(f"{name} must be a Path")
        if self.working_directory is not None and not isinstance(
            self.working_directory, Path
        ):
            raise DynamicApplicationError("working_directory must be a Path")
        if self.max_thread_events is not None and self.max_thread_events < 1:
            raise DynamicApplicationError("max_thread_events must be positive")
        for key, value in self.environment:
            if not isinstance(key, str) or not key or "\x00" in key:
                raise DynamicApplicationError("environment keys must be non-empty")
            if not isinstance(value, str) or "\x00" in value:
                raise DynamicApplicationError("environment values cannot contain NUL")


@dataclass(frozen=True, slots=True)
class AnalyzeRequest:
    trace_dir: Path
    dbt_contract: Path
    config: DynamicConfig

    def __post_init__(self) -> None:
        if not isinstance(self.trace_dir, Path) or not isinstance(self.dbt_contract, Path):
            raise DynamicApplicationError("trace_dir and dbt_contract must be Paths")
        if not isinstance(self.config, DynamicConfig):
            raise DynamicApplicationError("config must be DynamicConfig")


def _environment(request: CaptureRequest) -> Mapping[str, str]:
    return dict(request.environment)


def capture(request: CaptureRequest) -> TraceManifest:
    """启动一次原生采集并返回 manifest；不在 service 中渲染 JSON。"""

    return capture_program(
        request.command,
        request.output_dir,
        dynamorio_home=request.dynamorio_home,
        client_path=request.client_path,
        environment=dict(_environment(request)),
        working_directory=request.working_directory,
        max_thread_events=request.max_thread_events,
    )


def analyze(request: AnalyzeRequest) -> DynamicCertificate:
    """读取一条 trace 并返回既有动态 certificate。"""

    return analyze_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        config=request.config,
    )


def characterize(request: AnalyzeRequest) -> WindowCharacterizationReport:
    """只运行 trace 导入、通信扫描和窗口构造，不执行 proof。"""

    return characterize_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        config=request.config,
    )


def candidate_slices(request: AnalyzeRequest) -> SliceCandidateReport:
    """只生成候选切片和 obligation ledger，不执行 proof。"""

    return candidate_slice_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        config=request.config,
    )


def slice_plan(request: AnalyzeRequest) -> SlicePlanReport:
    """只计算 obligation-preserving 分区计划，不执行 proof。"""

    return slice_plan_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        config=request.config,
    )


def obligation_bottleneck(request: AnalyzeRequest) -> TraceObligationBottleneckReport:
    """只表征 obligation 网络，不执行 proof 或改变窗口。"""

    return obligation_bottleneck_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        config=request.config,
    )


def cycle_relevance(request: AnalyzeRequest) -> TraceCycleRelevanceReport:
    """只表征坏环关系和 PPO 可达性，不执行 proof。"""

    return cycle_relevance_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        config=request.config,
    )


def ppo_reduction(request: AnalyzeRequest) -> TracePpoReductionReport:
    """生成可独立 replay 的 PPO reduction shadow 报告。"""

    return ppo_reduction_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        config=request.config,
    )


def ppo_replay(
    request: AnalyzeRequest,
    certificate: TracePpoReductionCertificate,
) -> TracePpoReductionReplayReport:
    """用原始 trace 独立重放 PPO reduction certificate。"""

    return ppo_replay_trace(
        request.trace_dir,
        dbt_contract=request.dbt_contract,
        certificate=certificate,
        config=request.config,
    )


__all__ = [
    "AnalyzeRequest",
    "CaptureRequest",
    "DynamicApplicationError",
    "analyze",
    "candidate_slices",
    "slice_plan",
    "obligation_bottleneck",
    "cycle_relevance",
    "ppo_reduction",
    "ppo_replay",
    "characterize",
    "capture",
]
