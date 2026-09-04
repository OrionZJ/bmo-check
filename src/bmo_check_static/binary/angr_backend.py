from __future__ import annotations

import logging
from dataclasses import dataclass

from bmo_check_static.model import ModuleFingerprint


class AngrBackendError(RuntimeError):
    pass


@dataclass(frozen=True)
class AngrModuleContext:
    project: object
    cfg: object
    module: ModuleFingerprint
    mapped_base: int
    linked_base: int
    min_addr: int
    max_addr: int
    angr_version: str

    def to_elf_pc(self, address: int) -> int:
        return int(address) - self.mapped_base + self.linked_base

    def to_rebased(self, pc: int) -> int:
        return int(pc) - self.linked_base + self.mapped_base

    def contains_rebased(self, address: int) -> bool:
        return self.min_addr <= int(address) <= self.max_addr


def load_cfg(module: ModuleFingerprint) -> AngrModuleContext:
    # angr 的可选 Unicorn 后端缺失不会影响 CFGFast。
    # 提前压低日志级别，避免把可选加速器诊断误报成分析失败。
    logging.getLogger("angr").setLevel(logging.CRITICAL)
    logging.getLogger("cle").setLevel(logging.CRITICAL)
    try:
        import angr

        project = angr.Project(module.path, auto_load_libs=False)
        cfg = project.analyses.CFGFast(
            normalize=True,
            data_references=True,
            resolve_indirect_jumps=True,
        )
        main_object = project.loader.main_object
        return AngrModuleContext(
            project=project,
            cfg=cfg,
            module=module,
            mapped_base=int(main_object.mapped_base),
            linked_base=int(main_object.linked_base),
            min_addr=int(main_object.min_addr),
            max_addr=int(main_object.max_addr),
            angr_version=str(angr.__version__),
        )
    except Exception as error:
        raise AngrBackendError(
            f"angr CFGFast failed for {module.path}: {error}"
        ) from error
