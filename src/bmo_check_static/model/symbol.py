from __future__ import annotations

from .common import StrictModel


class FunctionSymbolFact(StrictModel):
    # module_path/hash 防止把同名符号套到另一版动态库。
    module_path: str
    module_sha256: str
    # name 只用于绑定候选；最终实现仍由 pc/size 限定。
    name: str
    pc: int
    size: int
    # binding、visibility 和 table 用于判断 loader 能否替换该定义。
    binding: str
    visibility: str
    table: str


class RelocationFact(StrictModel):
    # module_path/hash 标识 relocation 所属的具体 ELF。
    module_path: str
    module_sha256: str
    # offset 是 loader 写入目标地址的槽位。
    offset: int
    # symbol_name 用于在实际依赖闭包中寻找定义。
    symbol_name: str
    # relocation_type 与 section 保留 loader 绑定依据。
    relocation_type: int
    section: str
    # weak undefined 可以合法绑定为空，不能一律报成未知目标。
    binding: str
    undefined: bool
