"""对本地 litmus ELF 逐个运行普通 static pipeline。

这个脚本只保存每个 ELF 的紧凑汇总，不把完整 ``ProgramSliceReport`` 或
herd 原始输出写入结果文件。这样中断后可以从已完成的 ELF 继续，也不会
因为一次性收集整个 corpus 而占满内存或 D 盘。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from bmo_check_static.application import StaticRequest, slice_report
from bmo_check_static.model import CheckerLimits
from bmo_check_static.proof.verifier import verify_portability


_SYNC_CACHE: dict[tuple[object, ...], Any] = {}
_SYNC_CACHE_INSTALLED = False


@dataclass(frozen=True, slots=True)
class CorpusCase:
    """一个源文件与生成 ELF 的路径绑定。"""

    source: Path
    elf: Path
    source_relative: str
    elf_relative: str


@dataclass(frozen=True, slots=True)
class SweepConfig:
    """worker 共享的只读配置，避免把 argparse 对象传入分析层。"""

    repository_root: Path
    dbt_contract: Path
    pthread_spec: Path
    function_effects: Path
    library_roots: tuple[Path, ...]
    scope: str
    provenance_instruction_limit: int | None
    dbt_revision: str
    max_events: int
    max_threads: int
    max_executions: int
    timeout_ms: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def discover_cases(corpus_root: Path) -> tuple[CorpusCase, ...]:
    """按生成脚本的相对路径建立一一对应关系，不依赖测试名称语义。"""

    source_root = (corpus_root / "tests" / "non-mixed-size").resolve()
    elf_root = (corpus_root / "elf-tests").resolve()
    if not source_root.is_dir() or not elf_root.is_dir():
        raise ValueError(
            "corpus must contain tests/non-mixed-size and elf-tests directories"
        )
    cases: list[CorpusCase] = []
    for source in sorted(source_root.rglob("*.litmus")):
        relative = source.relative_to(source_root)
        stem = relative.stem
        elf = elf_root / relative.parent / stem / f"{stem}.exe"
        cases.append(
            CorpusCase(
                source=source,
                elf=elf,
                source_relative=relative.as_posix(),
                elf_relative=(elf.relative_to(corpus_root)).as_posix(),
            )
        )
    return tuple(cases)


def _counts(unknowns: Iterable[Any]) -> dict[str, int]:
    """Count typed facts without retaining their potentially large payloads."""

    counts = Counter(
        getattr(item.kind, "value", str(item.kind)) for item in unknowns
    )
    return dict(sorted(counts.items()))


def _unknown_counts(report: Any) -> dict[str, int]:
    """Count every producer layer for compatibility with the v1 rows."""

    unknowns: list[Any] = list(report.unknowns)
    recovery = report.recovery
    unknowns.extend(recovery.manifest.unknowns)
    unknowns.extend(recovery.unknowns)
    if report.memory_events is not None:
        unknowns.extend(report.memory_events.unknowns)
    if report.shared_slice is not None:
        unknowns.extend(report.shared_slice.unknowns)
    return _counts(unknowns)


def _install_sync_cache() -> None:
    """在一个 worker 内复用同一版运行库的同步摘要。

    运行库只由 ELF 内容、两个契约文件和请求的 API 集决定；每个 litmus
    ELF 重算它会重复反汇编同一份 libc。缓存不改变摘要内容，只减少重复
    工作；不同库 hash 或契约路径仍然使用独立条目。
    """

    global _SYNC_CACHE_INSTALLED
    if _SYNC_CACHE_INSTALLED:
        return
    import bmo_check_static.application as application

    original = application.analyze_pthread_synchronization

    def cached(*args: Any, **kwargs: Any) -> Any:
        library = args[0] if args else kwargs.get("library")
        pthread_spec = args[1] if len(args) > 1 else kwargs.get("pthread_spec_path")
        dbt_contract = args[2] if len(args) > 2 else kwargs.get("dbt_contract_path")
        requested = args[3] if len(args) > 3 else kwargs.get("requested_apis")
        key = (
            getattr(library, "sha256", None),
            str(pthread_spec),
            str(dbt_contract),
            tuple(sorted(requested)) if requested is not None else None,
            kwargs.get("canonical_scope", "static.synchronization"),
        )
        if key not in _SYNC_CACHE:
            _SYNC_CACHE[key] = original(*args, **kwargs)
        return _SYNC_CACHE[key]

    application.analyze_pthread_synchronization = cached
    _SYNC_CACHE_INSTALLED = True


def _analyze_case(payload: tuple[CorpusCase, SweepConfig]) -> dict[str, Any]:
    case, config = payload
    started = time.monotonic()
    base: dict[str, Any] = {
        "source_relative": case.source_relative,
        "elf_relative": case.elf_relative,
        "status": "error",
    }
    try:
        _install_sync_cache()
        if not case.source.is_file():
            raise FileNotFoundError(f"source litmus does not exist: {case.source}")
        if not case.elf.is_file():
            raise FileNotFoundError(f"ELF does not exist: {case.elf}")
        request = StaticRequest(
            executable=case.elf,
            dbt_contract=config.dbt_contract,
            pthread_spec=config.pthread_spec,
            function_effects=config.function_effects,
            library_roots=config.library_roots,
            scope=config.scope,
            provenance_instruction_limit=config.provenance_instruction_limit,
            dbt_revision=config.dbt_revision,
        )
        report = slice_report(request)
        checker = verify_portability(
            report,
            CheckerLimits(
                max_events=config.max_events,
                max_threads=config.max_threads,
                max_executions=config.max_executions,
                timeout_ms=config.timeout_ms,
            ),
            analysis_options={"scope": config.scope},
        )
        memory_events = report.memory_events.events if report.memory_events else ()
        shared_events = report.shared_slice.events if report.shared_slice else ()
        roles = report.recovery.thread_roles.roles if report.recovery.thread_roles else ()
        base.update(
            {
                "status": "completed",
                "verdict": checker.verdict.value,
                "checker_conclusion": checker.checker.conclusion.value,
                "checker_reason": checker.checker.reason,
                "examined_executions": checker.checker.examined_executions,
                "memory_events": len(memory_events),
                "shared_events": len(shared_events),
                "thread_roles": len(roles),
                # ``unknowns`` is the producer-layer union kept for v1
                # comparisons.  ``relevant_unknowns`` is the exact set that
                # verify_portability allowed to block this certificate.
                "unknowns": _unknown_counts(report),
                "relevant_unknowns": _counts(checker.relevant_unknowns),
                "source_sha256": _sha256(case.source),
                "elf_sha256": _sha256(case.elf),
            }
        )
    except Exception as error:  # pragma: no cover - exercised by corpus failures
        base["error"] = f"{type(error).__name__}: {error}"[:2000]
    base["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return base


def _read_completed(output: Path) -> set[str]:
    if not output.is_file():
        return set()
    completed: set[str] = set()
    with output.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict) and payload.get("status") in {
                "completed",
                "error",
            }:
                elf = payload.get("elf_relative")
                if isinstance(elf, str):
                    completed.add(elf)
    return completed


def _write_record(stream: Any, record: dict[str, Any]) -> None:
    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    stream.flush()


def _summary(output: Path, *, total: int, skipped: int) -> dict[str, Any]:
    statuses: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    unknowns: Counter[str] = Counter()
    relevant_unknowns: Counter[str] = Counter()
    elapsed = 0.0
    processed = 0
    with output.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            processed += 1
            statuses[str(payload.get("status", "unknown"))] += 1
            if payload.get("verdict") is not None:
                verdicts[str(payload["verdict"])] += 1
            for kind, count in (payload.get("unknowns") or {}).items():
                unknowns[str(kind)] += int(count)
            for kind, count in (payload.get("relevant_unknowns") or {}).items():
                relevant_unknowns[str(kind)] += int(count)
            elapsed += float(payload.get("elapsed_seconds", 0.0))
    return {
        "schema": "e2.5-static-corpus-sweep-v1",
        "total_cases": total,
        "records_in_output": processed,
        "skipped_from_resume": skipped,
        "statuses": dict(sorted(statuses.items())),
        "verdicts": dict(sorted(verdicts.items())),
        "unknown_kinds": dict(sorted(unknowns.items())),
        "relevant_unknown_kinds": dict(sorted(relevant_unknowns.items())),
        "sum_case_seconds": round(elapsed, 3),
    }


def run_sweep(
    cases: Iterable[CorpusCase],
    config: SweepConfig,
    output: Path,
    *,
    workers: int,
    resume: bool,
) -> dict[str, Any]:
    cases = tuple(cases)
    if workers < 1 or workers > 2:
        raise ValueError("workers must be 1 or 2; each static worker can use about 2.5GB")
    output.parent.mkdir(parents=True, exist_ok=True)
    completed = _read_completed(output) if resume else set()
    pending = tuple(case for case in cases if case.elf_relative not in completed)
    mode = "a" if resume else "w"
    skipped = len(cases) - len(pending)
    with output.open(mode, encoding="utf-8", buffering=1) as stream:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(_analyze_case, (case, config)): case for case in pending
            }
            try:
                for future in as_completed(futures):
                    _write_record(stream, future.result())
            except KeyboardInterrupt:
                for future in futures:
                    future.cancel()
                raise
    summary = _summary(output, total=len(cases), skipped=skipped)
    summary_path = output.with_suffix(output.suffix + ".summary.json")
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def _path_list(values: list[str]) -> tuple[Path, ...]:
    return tuple(Path(value).resolve() for value in values)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="stream all generated litmus ELF through BMoCheck static recovery"
    )
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path(__file__).parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dbt-contract", type=Path)
    parser.add_argument("--pthread-spec", type=Path)
    parser.add_argument("--function-effects", type=Path)
    parser.add_argument("--library-root", action="append", default=[])
    parser.add_argument("--scope", choices=("full", "application"), default="application")
    parser.add_argument("--provenance-instruction-limit", type=int, default=32)
    parser.add_argument("--dbt-revision", default="local-e2-5-corpus-sweep")
    parser.add_argument("--max-events", type=int, default=24)
    parser.add_argument("--max-threads", type=int, default=8)
    parser.add_argument("--max-executions", type=int, default=128)
    parser.add_argument("--timeout-ms", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--no-resume", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repository_root = args.repository_root.resolve()
    config = SweepConfig(
        repository_root=repository_root,
        dbt_contract=(args.dbt_contract or repository_root / "specs/static/dbt6-mo-off.yaml").resolve(),
        pthread_spec=(args.pthread_spec or repository_root / "specs/static/pthread-api.yaml").resolve(),
        function_effects=(args.function_effects or repository_root / "specs/static/library-effects.yaml").resolve(),
        library_roots=_path_list(args.library_root),
        scope=args.scope,
        provenance_instruction_limit=args.provenance_instruction_limit,
        dbt_revision=args.dbt_revision,
        max_events=args.max_events,
        max_threads=args.max_threads,
        max_executions=args.max_executions,
        timeout_ms=args.timeout_ms,
    )
    cases = discover_cases(args.corpus_root.resolve())
    summary = run_sweep(
        cases,
        config,
        args.output.resolve(),
        workers=args.workers,
        resume=not args.no_resume,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CorpusCase", "SweepConfig", "discover_cases", "run_sweep"]
