from __future__ import annotations

from enum import Enum

from pydantic import model_validator

from .common import StrictModel
from .unknown import UnknownFact


class CodeLocation(StrictModel):
    # path 与 hash 一起防止同一 PC 被错误复用到另一版二进制。
    module_path: str
    module_sha256: str
    # pc 使用 ELF 虚拟地址，不能混入 angr 的 rebased 地址。
    pc: int
    # symbol 只帮助解释报告，不作为地址正确性的证明。
    symbol: str | None = None


class IndirectTargetSet(StrictModel):
    # known_targets 可以是过近似候选；它不等于目标集合已经封闭。
    known_targets: tuple[CodeLocation, ...] = ()
    # 只有 relocation、固定表等封闭证据才能把 complete 设为 true。
    complete: bool
    # evidence 记录 complete 依赖的二进制事实，便于审计 false SAFE。
    evidence: tuple[str, ...] = ()
    # 不完整集合必须说明缺口，后续 proof 据此传播 Unknown。
    reason: str | None = None

    @model_validator(mode="after")
    def require_incomplete_reason(self) -> "IndirectTargetSet":
        if not self.complete and not self.reason:
            raise ValueError("incomplete target set requires a reason")
        return self


class CallKind(str, Enum):
    # DIRECT 的目标编码在 call 指令中。
    DIRECT = "direct"
    # PLT 目标仍需在实际依赖闭包中绑定实现。
    PLT = "plt"
    # INDIRECT 必须另附目标集合封闭证据。
    INDIRECT = "indirect"


class BasicBlockFact(StrictModel):
    # location 指向块首地址。
    location: CodeLocation
    # size 限定块覆盖范围，防止把相邻数据或代码并入块内。
    size: int
    # instruction_pcs 让后续层回查 Capstone 原始事实。
    instruction_pcs: tuple[int, ...] = ()
    # successor_pcs 只保存主 ELF 内已恢复的后继。
    successor_pcs: tuple[int, ...] = ()


class CallSite(StrictModel):
    # location 指向真实 call 指令，而不是所在基本块。
    location: CodeLocation
    # containing_function_pc 用于线程角色和调用图归属。
    containing_function_pc: int
    # block_pc 让 reaching-definition 分析定位调用前指令。
    block_pc: int
    # kind 区分直接、PLT 和仍需封闭证明的间接调用。
    kind: CallKind
    # target_symbol 来自 ELF/PLT；缺失时不能根据名称猜 callee。
    target_symbol: str | None = None
    # targets 同时保存候选集合与完整性。
    targets: IndirectTargetSet
    # return_pc 缺失表示 CFG 没有证明调用会正常返回。
    return_pc: int | None = None


class FunctionFact(StrictModel):
    # location 指向函数入口，并可携带符号名用于解释。
    location: CodeLocation
    # size 来自 CFG 恢复范围，不替代 ELF symbol size。
    size: int
    # block_pcs 组成当前恢复到的函数体。
    block_pcs: tuple[int, ...] = ()
    # returning=None 表示 angr 没有确定返回行为。
    returning: bool | None = None
    # PLT stub 不应被后续层误当成实际函数实现。
    is_plt: bool = False


class IndirectSiteFact(StrictModel):
    # location 指向间接 call/jump 指令。
    location: CodeLocation
    # 某些入口桩无法可靠归属函数，因此允许为空。
    containing_function_pc: int | None = None
    # control_flow 保留 call/jmp 类别，决定后续未知 effect。
    control_flow: str
    # targets 不完整时必须阻止后续层假定所有代码已覆盖。
    targets: IndirectTargetSet


class CFGCoverage(StrictModel):
    # angr_version 使恢复差异能够追溯到具体后端版本。
    angr_version: str
    # 以下计数用于发现意外的空分析或覆盖骤降。
    functions: int
    basic_blocks: int
    call_sites: int
    indirect_sites: int
    # complete/incomplete 分开计数，候选目标不会伪装成完整覆盖。
    complete_indirect_sites: int
    incomplete_indirect_sites: int


class ControlFlowReport(StrictModel):
    # schema_version 让缓存报告升级时能够拒绝旧字段含义。
    schema_version: int = 1
    # module_path/hash 绑定本报告分析的主 ELF。
    module_path: str
    module_sha256: str
    # entry_pc 是 ELF 地址空间中的进程入口。
    entry_pc: int
    # functions、basic_blocks 和 call_sites 保存恢复到的结构事实。
    functions: tuple[FunctionFact, ...] = ()
    basic_blocks: tuple[BasicBlockFact, ...] = ()
    call_sites: tuple[CallSite, ...] = ()
    # indirect_sites 单独保留每个目标集合的封闭状态。
    indirect_sites: tuple[IndirectSiteFact, ...] = ()
    # coverage 用计数检查恢复结果是否异常退化。
    coverage: CFGCoverage
    # unknowns 传播无法封闭的间接控制流和后端失败。
    unknowns: tuple[UnknownFact, ...] = ()
