"""把原始动态 trace 适配成 core 的只读诊断 snapshot。

适配器只聚合每个线程/站点的观察，不把整条轨迹复制到 Python 对象中。遇到
无法归一化的模块、截断记录或站点预算耗尽时，结果保留已采集观察并追加
trace-bound ``UnknownFact``；不完整 snapshot 不能被报告层当成完整执行。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from elftools.common.exceptions import ELFError

from bmo_check_core import (
    BinaryClosureId,
    DynamicDiagnosticSnapshot,
    EvidenceAttribute,
    EvidenceSnapshot,
    InstructionId,
    MemoryOperandId,
    ModuleId,
    ObservedFact,
    ProducerId,
    ThreadInstanceId,
    TraceId,
    UnknownFact,
    UnknownKind,
)

from ..model import EventKind, TraceEvent, TraceManifest
from ..trace import TraceReader, trace_digest, validate_trace
from ..trace.format import (
    HEADER,
    MAGIC,
    RECORD,
    VERSION_MAJOR,
    VERSION_MINOR,
    event_files,
)


class DynamicSnapshotAdapterError(ValueError):
    """动态 trace 缺少生成 canonical snapshot 所需身份时抛出的错误。"""


_PRODUCER = ProducerId("bmo-check-dynamic-snapshot", "d1")
_UNKNOWN_PRODUCER = ProducerId("bmo-check-dynamic-snapshot", "d1")
_MEMORY_LABELS = {
    EventKind.LOAD: "Load",
    EventKind.STORE: "Store",
    EventKind.ATOMIC_RMW: "AtomicRmw",
    EventKind.FUTEX_WAIT: "FutexWait",
}
_FENCE_LABELS = {
    EventKind.LFENCE: "Lfence",
    EventKind.SFENCE: "Sfence",
    EventKind.MFENCE: "Mfence",
}
_CONTROL_LABELS = {
    EventKind.INDIRECT_TARGET: "IndirectTarget",
    EventKind.SIGNAL: "Signal",
}

# 聚合器只保留少量首次地址和步长候选。超过上限时明确标记不完整，
# 这样大程序不会因为诊断而把整个访存序列复制到 Python 内存。
_ADDRESS_SAMPLE_LIMIT = 32
_STRIDE_CANDIDATE_LIMIT = 16
_INSTRUMENTATION_BASENAMES = frozenset({"libbmo_trace.so", "libdynamorio.so"})


def _event_label(kind: EventKind) -> str:
    return _MEMORY_LABELS.get(
        kind,
        _FENCE_LABELS.get(kind, _CONTROL_LABELS.get(kind, kind.name)),
    )


@dataclass(frozen=True, slots=True)
class _ModuleRange:
    start: int
    end: int
    path: str
    sha256: str
    role: str
    module_id: ModuleId
    # linked_base 把运行时 PC 转回静态 ELF 使用的虚拟地址。
    # 只减 mapping start 会在 ET_EXEC 上把所有指令错移一个固定基址。
    linked_base: int = 0


@dataclass(slots=True)
class _SiteAggregate:
    module: _ModuleRange
    offset: int
    thread_id: int
    kind: EventKind
    operand_index: int | None
    count: int = 0
    min_address: int | None = None
    max_end: int | None = None
    min_size: int | None = None
    max_size: int | None = None
    first_sequence: int | None = None
    last_sequence: int | None = None
    min_target: int | None = None
    max_target: int | None = None
    # distinct_addresses 是已见起始地址数量；样本封顶后只表示下界。
    distinct_addresses: int = 0
    # address_samples 只保留站点最先出现的少量地址，供诊断回查。
    address_samples: list[int] = field(default_factory=list)
    # address_sample_set 防止重复样本占用地址上限。
    address_sample_set: set[int] = field(default_factory=set)
    # 地址集合达到上限后置为 False，不能再声称集合完整。
    address_sample_complete: bool = True
    # previous_address 记录相邻事件，用于产生有符号差分候选。
    previous_address: int | None = None
    # stride_candidates 保存有界的相邻地址差分。
    stride_candidates: set[int] = field(default_factory=set)
    # 差分候选达到上限后置为 False，不能再声称步长集合完整。
    stride_complete: bool = True

    def add(self, event: TraceEvent) -> None:
        self.count += 1
        if self.first_sequence is None:
            self.first_sequence = event.sequence
        self.last_sequence = event.sequence
        if event.kind.is_memory:
            end = event.address + event.size
            self.min_address = (
                event.address
                if self.min_address is None
                else min(self.min_address, event.address)
            )
            self.max_end = end if self.max_end is None else max(self.max_end, end)
            self.min_size = (
                event.size
                if self.min_size is None
                else min(self.min_size, event.size)
            )
            self.max_size = (
                event.size
                if self.max_size is None
                else max(self.max_size, event.size)
            )
            if self.address_sample_complete:
                if event.address not in self.address_sample_set:
                    self.distinct_addresses += 1
                    if len(self.address_samples) < _ADDRESS_SAMPLE_LIMIT:
                        self.address_sample_set.add(event.address)
                        self.address_samples.append(event.address)
                    else:
                        # 只记录下界；继续保留计数不会泄露未界定的完整地址集合。
                        self.address_sample_complete = False
                        self.distinct_addresses = _ADDRESS_SAMPLE_LIMIT + 1
            elif self.distinct_addresses == _ADDRESS_SAMPLE_LIMIT + 1:
                # 样本已封顶，后续只保留“至少超过上限”这一事实。
                pass
            if self.previous_address is not None:
                delta = event.address - self.previous_address
                if delta != 0 and self.stride_complete:
                    if delta not in self.stride_candidates:
                        if len(self.stride_candidates) < _STRIDE_CANDIDATE_LIMIT:
                            self.stride_candidates.add(delta)
                        else:
                            self.stride_complete = False
            self.previous_address = event.address
        elif event.kind == EventKind.INDIRECT_TARGET:
            self.min_target = (
                event.address
                if self.min_target is None
                else min(self.min_target, event.address)
            )
            self.max_target = (
                event.address
                if self.max_target is None
                else max(self.max_target, event.address)
            )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise DynamicSnapshotAdapterError(f"cannot hash module {path}: {error}") from error
    return digest.hexdigest()


def _manifest_modules(manifest: TraceManifest) -> tuple[tuple[str, str, str], ...]:
    modules: list[tuple[str, str, str]] = [
        (manifest.executable.path, manifest.executable.sha256, "executable")
    ]
    for item in manifest.libraries:
        # DynamoRIO 的模块清单会把主 ELF 也记进 libraries；重复加入 shared_library
        # 会让动态闭包与静态闭包产生一个虚假的角色差异。
        if item.path == manifest.executable.path and item.sha256 == manifest.executable.sha256:
            continue
        modules.append((item.path, item.sha256, _module_role(item.path)))
    return tuple(modules)


def _module_role(path: str) -> str:
    """把动态 loader 从普通依赖中分出来，与静态闭包的角色一致。"""

    name = Path(path).name.casefold()
    if name.startswith("ld-linux") or name.startswith("ld-musl") or name in {
        "ld.so",
        "ld.so.1",
    }:
        return "interpreter"
    if (
        name in _INSTRUMENTATION_BASENAMES
        or name.startswith("libdynamorio.so.")
        or name.startswith("libbmo_trace.so.")
    ):
        return "instrumentation"
    return "shared_library"


def _linked_base(path: Path) -> int:
    """读取 ELF 的静态链接基址；测试用的非 ELF 文件回退到 0。"""

    try:
        from elftools.elf.elffile import ELFFile

        with path.open("rb") as stream:
            elf = ELFFile(stream)
            loads = tuple(
                int(segment.header.p_vaddr)
                for segment in elf.iter_segments()
                if segment.header.p_type == "PT_LOAD"
            )
    except (ImportError, OSError, ValueError, TypeError, ELFError):
        return 0
    return min(loads, default=0)


def _module_ranges(
    trace_dir: Path,
    manifest: TraceManifest,
    reasons: list[str],
    *,
    report_unbound: bool = True,
) -> tuple[_ModuleRange, ...]:
    known: dict[str, tuple[str, str]] = {}
    for path, sha256, role in _manifest_modules(manifest):
        known[path] = (sha256, role)
        try:
            known[str(Path(path).resolve())] = (sha256, role)
        except OSError:
            pass
    modules_path = trace_dir / "modules.tsv"
    if not modules_path.is_file():
        reasons.append("dynamic snapshot cannot normalize PCs without modules.tsv")
        return ()
    ranges: list[_ModuleRange] = []
    try:
        lines = modules_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        reasons.append(f"cannot read modules.tsv: {error}")
        return ()
    for line_number, line in enumerate(lines, 1):
        fields = line.split("\t", 2)
        if len(fields) != 3:
            reasons.append(f"invalid modules.tsv line {line_number}")
            continue
        try:
            start, end = int(fields[0], 16), int(fields[1], 16)
        except ValueError:
            reasons.append(f"invalid module range at line {line_number}")
            continue
        path = fields[2]
        if start < 0 or end <= start:
            reasons.append(f"invalid module range at line {line_number}")
            continue
        identity = known.get(path) or known.get(str(Path(path).resolve()))
        if identity is None and Path(path).is_file():
            try:
                identity = (_sha256(Path(path)), _module_role(path))
                known[path] = identity
            except DynamicSnapshotAdapterError as error:
                reasons.append(str(error))
        if identity is None:
            # vDSO/anonymous mappings have no stable ELF closure identity.
            if report_unbound:
                reasons.append(f"module has no bound fingerprint: {path}")
            continue
        sha256, role = identity
        try:
            module_id = ModuleId.from_parts(sha256, role)
        except ValueError as error:
            reasons.append(f"module hash is invalid for {path}: {error}")
            continue
        ranges.append(
            _ModuleRange(
                start,
                end,
                path,
                sha256,
                role,
                module_id,
                _linked_base(Path(path)) if Path(path).is_file() else 0,
            )
        )
    return tuple(sorted(set(ranges), key=lambda item: (item.start, item.end, item.path)))


def _trace_identity(
    trace_dir: Path,
    manifest: TraceManifest,
    ranges: tuple[_ModuleRange, ...],
    format_version: str,
) -> tuple[TraceId, BinaryClosureId | None]:
    manifest_digest = _sha256(trace_dir / "manifest.json")
    module_refs = _manifest_modules(manifest)
    for item in ranges:
        if (item.path, item.sha256, item.role) not in module_refs:
            module_refs += ((item.path, item.sha256, item.role),)
    module_ids = tuple(
        ModuleId.from_parts(sha256, role)
        for _path, sha256, role in module_refs
    )
    # DynamoRIO/client 只负责采集，不属于被证明的 guest 闭包；把它们放进
    # BinaryClosureId 会让同一程序的静态快照因插桩实现不同而永远无法匹配。
    closure_refs = tuple(
        (path, sha256, role)
        for path, sha256, role in module_refs
        if role != "instrumentation"
    )
    records_digest = trace_digest(trace_dir)
    try:
        trace_id = TraceId.from_parts(
            format_version,
            manifest_digest,
            module_ids,
            (manifest.trace_id, "complete" if manifest.complete else "incomplete"),
            records_digest,
        )
        closure = BinaryClosureId.from_parts(
            manifest.executable.sha256,
            tuple((role, sha256) for _path, sha256, role in closure_refs),
            "EM_X86_64:elf64:le",
        )
    except ValueError as error:
        raise DynamicSnapshotAdapterError(
            f"trace identity cannot be derived from manifest: {error}"
        ) from error
    return trace_id, closure


def _trace_format_version(trace_dir: Path) -> str:
    """读取所有 event 文件的 wire 版本，避免把 1.1 旧 trace 伪装成 1.2。"""

    versions: set[str] = set()
    for path in event_files(trace_dir):
        try:
            with path.open("rb") as stream:
                raw_header = stream.read(HEADER.size)
            if len(raw_header) != HEADER.size:
                continue
            magic, major, minor, record_size = HEADER.unpack(raw_header)
            if magic == MAGIC and major == VERSION_MAJOR and record_size == RECORD.size:
                versions.add(f"{major}.{minor}")
        except OSError:
            continue
    if not versions:
        return f"trace-{VERSION_MAJOR}.{VERSION_MINOR}"
    return "trace-" + "+".join(sorted(versions))


def _range_for_pc(
    ranges: tuple[_ModuleRange, ...],
    pc: int,
    reasons: list[str],
) -> _ModuleRange | None:
    candidates = tuple(item for item in ranges if item.start <= pc < item.end)
    if not candidates:
        reasons.append(f"PC 0x{pc:x} is outside loaded module ranges")
        return None
    identities = {(item.path, item.sha256) for item in candidates}
    if len(identities) > 1:
        reasons.append(f"PC 0x{pc:x} has ambiguous loaded module identity")
        return None
    return min(candidates, key=lambda item: (item.end - item.start, item.start))


def _unknown_kind(reasons: tuple[str, ...]) -> UnknownKind:
    text = " ".join(reasons).casefold()
    if any(token in text for token in ("unsupported", "no bound fingerprint", "outside loaded")):
        return UnknownKind.UNSUPPORTED_INPUT
    if any(token in text for token in ("budget", "limit", "exceed")):
        return UnknownKind.RESOURCE_LIMIT
    return UnknownKind.INCOMPLETE_RECOVERY


def _unknown(
    *,
    scope: str,
    trace_id: TraceId,
    reasons: tuple[str, ...],
) -> UnknownFact:
    return UnknownFact.create(
        schema_version="dynamic-unknown-v1",
        producer=_UNKNOWN_PRODUCER,
        kind=_unknown_kind(reasons),
        reason=reasons[0] if reasons else "dynamic snapshot is incomplete",
        subject=None,
        scope=scope,
        supporting_context=(f"trace_id={trace_id.value}", *reasons[1:]),
    )


def _observed_fact(
    aggregate: _SiteAggregate,
    trace_id: TraceId,
    *,
    scope: str,
) -> ObservedFact:
    instruction = InstructionId.from_parts(
        aggregate.module.module_id,
        aggregate.module.linked_base + aggregate.offset,
    )
    if aggregate.kind.is_memory and aggregate.operand_index is not None:
        subject = MemoryOperandId.from_parts(
            instruction,
            aggregate.operand_index,
            _MEMORY_LABELS[aggregate.kind],
        )
    else:
        # 旧 trace 没有 operand discriminator，只能落到 instruction site；
        # correlator 会在多 operand 时保留 Ambiguous，而不是猜 index=0。
        subject = instruction
    attributes = [
        EvidenceAttribute("module_path", aggregate.module.path),
        EvidenceAttribute("module_sha256", aggregate.module.sha256),
        EvidenceAttribute("instruction_offset", f"0x{aggregate.offset:x}"),
        EvidenceAttribute(
            "elf_pc",
            f"0x{aggregate.module.linked_base + aggregate.offset:x}",
        ),
        EvidenceAttribute("event_kind", _event_label(aggregate.kind)),
        EvidenceAttribute("sample_count", str(aggregate.count)),
    ]
    if aggregate.operand_index is None and aggregate.kind.is_memory:
        attributes.append(EvidenceAttribute("operand_identity", "missing"))
    elif aggregate.operand_index is not None:
        attributes.append(EvidenceAttribute("operand_index", str(aggregate.operand_index)))
    if aggregate.min_address is not None and aggregate.max_end is not None:
        attributes.extend(
            (
                EvidenceAttribute("address_min", f"0x{aggregate.min_address:x}"),
                EvidenceAttribute("address_max_end", f"0x{aggregate.max_end:x}"),
                EvidenceAttribute("size_min", str(aggregate.min_size or 0)),
                EvidenceAttribute("size_max", str(aggregate.max_size or 0)),
            )
        )
        attributes.extend(
            (
                EvidenceAttribute(
                    "address_distinct_count", str(aggregate.distinct_addresses)
                ),
                EvidenceAttribute(
                    "address_samples",
                    ",".join(f"0x{value:x}" for value in aggregate.address_samples)
                    or "none",
                ),
                EvidenceAttribute(
                    "address_sample_complete",
                    str(aggregate.address_sample_complete).lower(),
                ),
                EvidenceAttribute(
                    "address_sample_limit", str(_ADDRESS_SAMPLE_LIMIT)
                ),
                EvidenceAttribute(
                    "stride_candidates",
                    ",".join(str(value) for value in sorted(aggregate.stride_candidates))
                    or "none",
                ),
                EvidenceAttribute(
                    "stride_candidates_complete",
                    str(aggregate.stride_complete).lower(),
                ),
            )
        )
    if aggregate.first_sequence is not None and aggregate.last_sequence is not None:
        attributes.extend(
            (
                EvidenceAttribute("sequence_first", str(aggregate.first_sequence)),
                EvidenceAttribute("sequence_last", str(aggregate.last_sequence)),
            )
        )
    if aggregate.min_target is not None and aggregate.max_target is not None:
        attributes.extend(
            (
                EvidenceAttribute("target_min", f"0x{aggregate.min_target:x}"),
                EvidenceAttribute("target_max", f"0x{aggregate.max_target:x}"),
            )
        )
    execution = ThreadInstanceId.from_parts(trace_id, aggregate.thread_id)
    if aggregate.kind in _FENCE_LABELS:
        observation_kind = "explicit-fence"
    elif aggregate.kind == EventKind.ATOMIC_RMW:
        observation_kind = "atomic-boundary"
    elif aggregate.kind == EventKind.INDIRECT_TARGET:
        observation_kind = "indirect-target"
    elif aggregate.kind == EventKind.SIGNAL:
        observation_kind = "signal"
    else:
        observation_kind = "memory-site"
    return ObservedFact.create(
        schema_version="dynamic-observed-v1",
        producer=_PRODUCER,
        trace_id=trace_id,
        execution_id=execution,
        subject=subject,
        observation_kind=observation_kind,
        attributes=tuple(attributes),
    )


def dynamic_snapshot_from_trace(
    trace_dir: Path,
    *,
    scope: str = "dynamic.trace",
    max_sites: int = 100_000,
    site_filter: set[tuple[str, int]] | None = None,
) -> DynamicDiagnosticSnapshot:
    """流式读取一个 trace 目录并生成 canonical DynamicDiagnosticSnapshot。

    ``site_filter`` 只限制保留哪些模块相对 PC；原始文件仍会完整扫描，因而
    不会把过滤掉的执行路径误报成已证明。它用于诊断已知静态缺口，避免为一次
    回查保留大型程序的所有站点。
    """

    if not isinstance(trace_dir, Path):
        raise DynamicSnapshotAdapterError("trace_dir must be a Path")
    if not isinstance(scope, str) or not scope or "\x00" in scope:
        raise DynamicSnapshotAdapterError("dynamic snapshot scope must be non-empty")
    if isinstance(max_sites, bool) or not isinstance(max_sites, int) or max_sites < 1:
        raise DynamicSnapshotAdapterError("max_sites must be positive")
    if site_filter is not None:
        try:
            filter_items = tuple(site_filter)
        except TypeError as error:
            raise DynamicSnapshotAdapterError(
                "site_filter must contain (module path, non-negative offset) pairs"
            ) from error
        for item in filter_items:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or not item[0]
                or isinstance(item[1], bool)
                or not isinstance(item[1], int)
                or item[1] < 0
            ):
                raise DynamicSnapshotAdapterError(
                    "site_filter must contain (module path, non-negative offset) pairs"
                )
        site_filter = set(filter_items)
    try:
        manifest = TraceManifest.load(trace_dir / "manifest.json")
    except (OSError, ValueError) as error:
        raise DynamicSnapshotAdapterError(f"invalid trace manifest: {error}") from error
    validation = validate_trace(trace_dir)
    reasons = list(validation.reasons)
    # manifest.complete 只是 launcher 的最终摘要；真正表示 client 已经 flush
    # 并关闭所有线程文件的是尾部 marker。两者不同时不能把轨迹交给诊断当完整证据。
    marker = trace_dir / ".complete"
    if manifest.complete and not marker.is_file():
        reasons.append("trace is missing the completion marker")
    elif not manifest.complete and marker.is_file():
        reasons.append("incomplete trace has a completion marker")
    # 诊断 site filter 只回查指定静态站点；未绑定的 vDSO/匿名映射若没有
    # 命中这些站点，不应让一个本来完整的 trace 被无关运行库事件标成不完整。
    ranges = _module_ranges(
        trace_dir,
        manifest,
        reasons,
        report_unbound=site_filter is None,
    )
    trace_id, closure = _trace_identity(
        trace_dir,
        manifest,
        ranges,
        _trace_format_version(trace_dir),
    )
    aggregates: dict[tuple[str, int, int, EventKind, int | None], _SiteAggregate] = {}
    budget_exhausted = False
    for path in event_files(trace_dir):
        try:
            events = TraceReader(path)
            for event in events:
                if not (
                    event.kind.is_memory
                    or event.kind in _FENCE_LABELS
                    or event.kind in _CONTROL_LABELS
                ):
                    continue
                if site_filter is not None and not any(
                    item.start <= event.pc < item.end
                    and (item.path, event.pc - item.start) in site_filter
                    for item in ranges
                ):
                    continue
                module = _range_for_pc(ranges, event.pc, reasons) if event.pc else None
                if module is None:
                    continue
                offset = event.pc - module.start
                if site_filter is not None and (module.path, offset) not in site_filter:
                    continue
                operand_index = event.operand_index if event.kind.is_memory else None
                key = (module.path, offset, event.thread_id, event.kind, operand_index)
                aggregate = aggregates.get(key)
                if aggregate is None:
                    if len(aggregates) >= max_sites:
                        budget_exhausted = True
                        continue
                    aggregate = _SiteAggregate(
                        module=module,
                        offset=offset,
                        thread_id=event.thread_id,
                        kind=event.kind,
                        operand_index=operand_index,
                    )
                    aggregates[key] = aggregate
                aggregate.add(event)
        except (OSError, ValueError) as error:
            reasons.append(f"cannot decode trace file {path.name}: {error}")
    if budget_exhausted:
        reasons.append(f"dynamic snapshot site budget exceeded: {max_sites}")
    observations = tuple(
        _observed_fact(item, trace_id, scope=scope)
        for item in sorted(
            aggregates.values(),
            key=lambda item: (
                item.module.path,
                item.offset,
                item.thread_id,
                item.kind.value,
                item.operand_index if item.operand_index is not None else -1,
            ),
        )
    )
    unknowns = (_unknown(scope=scope, trace_id=trace_id, reasons=tuple(dict.fromkeys(reasons))),) if reasons else ()
    complete = manifest.complete and validation.valid and not reasons
    return DynamicDiagnosticSnapshot(
        schema_version="dynamic-diagnostic-v1",
        trace_id=trace_id,
        scope=scope,
        complete=complete,
        evidence=EvidenceSnapshot(nodes=(*observations, *unknowns)),
        binary_closure=closure,
    )


__all__ = [
    "DynamicSnapshotAdapterError",
    "dynamic_snapshot_from_trace",
]
