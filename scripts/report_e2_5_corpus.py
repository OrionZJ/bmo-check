"""在不把全量结果读入内存的前提下汇总 E2.5 static corpus sweep。

跑批每个 ELF 只写一条紧凑记录。本报告只统计这些记录和 typed Unknown 名称，
不会重建 ProofFact，也不会改变 analyzer verdict。``first_blocker`` 只是记录中
最早出现的 pipeline 层；紧凑格式没有保留 Unknown 的来源链，因此它不是因果证明。
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


# 顺序沿用 static service：闭包/CFG/线程恢复、事件提取、共享切片、有限 checker。
# 把这个表放在汇总器里，是为了公开“首层阻塞”的测量约定，不能把数量最多的
# 下游事实悄悄当成根因。
LAYER_ORDER: tuple[str, ...] = (
    "recovery",
    "memory_events",
    "sharing",
    "checker",
)

UNKNOWN_LAYER: dict[str, str] = {
    "MissingExecutable": "recovery",
    "InvalidElf": "recovery",
    "UnsupportedArchitecture": "recovery",
    "MissingInterpreter": "recovery",
    "MissingLibrary": "recovery",
    "AmbiguousLibrary": "recovery",
    "ElfBackendFailure": "recovery",
    "DisassemblyFailure": "recovery",
    "IncompleteInstructionFact": "recovery",
    "UnresolvedIndirectCall": "recovery",
    "UnknownThreadEntry": "recovery",
    "UnknownJoinRelation": "recovery",
    "UnknownThreadRole": "recovery",
    "UnknownSynchronization": "recovery",
    "CfgBackendFailure": "recovery",
    "IncompleteIndirectTarget": "recovery",
    "MissingSymbolImplementation": "recovery",
    "ReachingDefinitionFailure": "recovery",
    "MemoryEventRecoveryFailure": "memory_events",
    "UnknownMemoryEffect": "memory_events",
    "UnknownSharedAddress": "memory_events",
    "UnknownEscape": "sharing",
    "UnknownAffineBounds": "sharing",
    "UnsupportedPortabilityInput": "checker",
    "PortabilityCheckIncomplete": "checker",
    "PortabilityCheckTimeout": "checker",
    "PortabilityCheckBound": "checker",
    "MissingDbtRevision": "checker",
    "InvalidDbtContract": "checker",
}

CHECKER_BOUNDARY_KINDS = {
    "UnsupportedPortabilityInput",
    "PortabilityCheckIncomplete",
    "PortabilityCheckTimeout",
    "PortabilityCheckBound",
    "MissingDbtRevision",
    "InvalidDbtContract",
}


def _iter_rows(path: Path) -> Iterable[dict[str, Any]]:
    """逐行读取对象记录；只跳过损坏或被截断的行。"""

    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # 进程被中断时最后一行可能不完整。调用方会记录输入不完整，
                # 不能把它悄悄算成已完成的 ELF。
                continue
            if isinstance(row, dict):
                yield row


def _unknowns(row: dict[str, Any], key: str = "relevant_unknowns") -> dict[str, int]:
    values = row.get(key)
    if not isinstance(values, dict) and key != "unknowns":
        # v1 rows没有 relevant_unknowns；回退到 producer-layer union，
        # 并在输出 schema 中保留这个兼容事实。
        values = row.get("unknowns")
    if not isinstance(values, dict):
        return {}
    result: dict[str, int] = {}
    for kind, count in values.items():
        if not isinstance(kind, str):
            continue
        try:
            result[kind] = int(count)
        except (TypeError, ValueError):
            # 这一行仍可计入记录数，但非数字值不能冒充 typed occurrence count。
            continue
    return result


def _first_blocker(kinds: set[str]) -> tuple[str, tuple[str, ...]]:
    layers = {
        layer: sorted(kind for kind in kinds if UNKNOWN_LAYER.get(kind) == layer)
        for layer in LAYER_ORDER
    }
    for layer in LAYER_ORDER:
        if layers[layer]:
            return layer, tuple(layers[layer])
    return "unclassified", tuple(sorted(kinds))


def summarize(path: Path, *, expected_total: int | None = None) -> dict[str, Any]:
    """从紧凑记录生成有界大小的测量报告。"""

    digest = hashlib.sha256()
    records = 0
    malformed_lines = 0
    statuses: Counter[str] = Counter()
    verdicts: Counter[str] = Counter()
    conclusions: Counter[str] = Counter()
    unknown_occurrences: Counter[str] = Counter()
    unknown_affected: dict[str, set[str]] = {}
    all_unknown_occurrences: Counter[str] = Counter()
    all_unknown_affected: dict[str, set[str]] = {}
    unknown_combinations: Counter[tuple[str, ...]] = Counter()
    thread_role_counts: Counter[str] = Counter()
    memory_event_counts: Counter[str] = Counter()
    shared_event_counts: Counter[str] = Counter()
    first_layers: Counter[str] = Counter()
    first_kinds: Counter[tuple[str, ...]] = Counter()
    checker_boundary_elfs: set[str] = set()
    recovery_failures: set[str] = set()
    recovery_reached = 0
    thread_closed = 0
    shared_closed = 0
    checker_reached = 0

    with path.open("rb") as raw:
        for raw_line in raw:
            digest.update(raw_line)
            try:
                row = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                malformed_lines += 1
                continue
            if not isinstance(row, dict):
                malformed_lines += 1
                continue
            records += 1
            status = str(row.get("status", "unknown"))
            statuses[status] += 1
            elf = row.get("elf_relative")
            elf_id = elf if isinstance(elf, str) else f"<row:{records}>"
            verdict = row.get("verdict")
            if verdict is not None:
                verdicts[str(verdict)] += 1
            conclusion = row.get("checker_conclusion")
            if conclusion is not None:
                conclusions[str(conclusion)] += 1
            if isinstance(row.get("thread_roles"), int):
                thread_role_counts[str(row["thread_roles"])] += 1
            if isinstance(row.get("memory_events"), int):
                memory_event_counts[str(row["memory_events"])] += 1
            if isinstance(row.get("shared_events"), int):
                shared_event_counts[str(row["shared_events"])] += 1

            all_kinds_with_counts = _unknowns(row, "unknowns")
            kinds_with_counts = _unknowns(row, "relevant_unknowns")
            for kind, count in all_kinds_with_counts.items():
                all_unknown_occurrences[kind] += count
                all_unknown_affected.setdefault(kind, set()).add(elf_id)
            kinds = set(kinds_with_counts)
            for kind, count in kinds_with_counts.items():
                unknown_occurrences[kind] += count
                unknown_affected.setdefault(kind, set()).add(elf_id)
            if kinds:
                unknown_combinations[tuple(sorted(kinds))] += 1
            layer, first = _first_blocker(kinds)
            first_layers[layer] += 1
            first_kinds[first] += 1

            completed = status == "completed"
            if completed:
                recovery_reached += 1
                recovery_kinds = {
                    kind for kind in kinds if UNKNOWN_LAYER.get(kind) == "recovery"
                }
                memory_kinds = {
                    kind
                    for kind in kinds
                    if UNKNOWN_LAYER.get(kind) in {"memory_events", "sharing"}
                }
                if not recovery_kinds:
                    thread_closed += 1
                if not memory_kinds:
                    shared_closed += 1
                if verdict is not None:
                    checker_reached += 1
            else:
                # ``run_e2_5_corpus_sweep`` 在整个 service 调用外层捕获异常，
                # error 行不足以定位失败阶段。这里保留为 pipeline error，
                # 不猜测是 recovery 阶段失败。
                recovery_failures.add(elf_id)
            if kinds.intersection(CHECKER_BOUNDARY_KINDS):
                checker_boundary_elfs.add(elf_id)

    def counter_values(counter: Counter[str]) -> dict[str, int]:
        return dict(sorted(counter.items()))

    return {
        "schema": "e2.5-static-corpus-measurement-v1",
        "input": {
            "path": str(path),
            "sha256": digest.hexdigest(),
            "records": records,
            "malformed_or_truncated_lines": malformed_lines,
            "expected_total": expected_total,
            "complete": (
                expected_total is not None
                and records == expected_total
                and malformed_lines == 0
            ),
        },
        "coverage": {
            # 这些是记录级操作指标。紧凑 schema 没有阶段时间戳，不能把它们读成
            # 某个前置阶段已经关闭全部 proof obligation。
            "recovery_reached": recovery_reached,
            "thread_recovery_closed": thread_closed,
            "shared_event_recovery_closed": shared_closed,
            "checker_reached": checker_reached,
        },
        "statuses": counter_values(statuses),
        "verdicts": counter_values(verdicts),
        "checker_conclusions": counter_values(conclusions),
        "observed_shape": {
            "thread_role_count_rows": counter_values(thread_role_counts),
            "memory_event_count_rows": counter_values(memory_event_counts),
            "shared_event_count_rows": counter_values(shared_event_counts),
        },
        "failure_classes": {
            "pipeline_error_elfs": len(recovery_failures),
            "recovery_failure_elfs": "not_stage_separated",
            "checker_boundary_elfs": len(checker_boundary_elfs),
            "stage_resolution": (
                "compact sweep 只记录整个 service 的一个 error 字段；要区分阶段，"
                "需要更丰富的 row schema"
            ),
            # 这次 sweep 不运行 herd 或第二个 checker。显式写出“未测量”，
            # 防止把没有测量的 mismatch 误写成零。
            "oracle_mismatch": "not_measured_by_static_sweep",
        },
        "unknowns": {
            "affected_elfs": {
                kind: len(elfs) for kind, elfs in sorted(unknown_affected.items())
            },
            "total_occurrences": counter_values(unknown_occurrences),
            "unknown_without_layer": sorted(
                kind for kind in unknown_occurrences if kind not in UNKNOWN_LAYER
            ),
        },
        "all_producer_unknowns": {
            "affected_elfs": {
                kind: len(elfs)
                for kind, elfs in sorted(all_unknown_affected.items())
            },
            "total_occurrences": counter_values(all_unknown_occurrences),
            "interpretation": (
                "all producer-layer facts; relevant_unknowns is the checker blocking set"
            ),
        },
        "first_blocker_observation": {
            "layer_counts": counter_values(first_layers),
            "kind_set_counts": {
                "+".join(kinds) if kinds else "<none>": count
                for kinds, count in sorted(first_kinds.items())
            },
            "interpretation": (
                "earliest observed layer in the compact row; not a causal proof"
            ),
        },
        "cooccurrence": [
            {"kinds": list(kinds), "affected_elfs": count}
            for kinds, count in unknown_combinations.most_common()
        ],
        "causal_evidence": {
            "proven": [],
            "possible_upstream": [
                {
                    "upstream": "ReachingDefinitionFailure",
                    "downstream": [
                        "UnknownMemoryEffect",
                        "UnknownEscape",
                        "UnknownAffineBounds",
                    ],
                    "basis": "same ELF co-occurrence only; compact rows omit provenance links",
                },
                {
                    "upstream": "UnknownThreadEntry",
                    "downstream": ["UnknownMemoryEffect", "UnknownEscape"],
                    "basis": "same ELF co-occurrence only; worker event propagation is not recorded",
                },
            ],
            "unresolved": [
                "UnknownMemoryEffect versus UnknownEscape/UnknownAffineBounds causal direction",
                "UnknownJoinRelation versus synchronization/lifecycle effects",
            ],
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="compact JSONL from run_e2_5_corpus_sweep")
    parser.add_argument("--expected-total", type=int, default=2595)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = summarize(args.input, expected_total=args.expected_total)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["summarize", "UNKNOWN_LAYER", "LAYER_ORDER"]
