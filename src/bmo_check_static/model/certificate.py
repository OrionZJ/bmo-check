from __future__ import annotations

from pydantic import Field, model_validator

from .common import StrictModel
from .sharing import ProofObject
from .unknown import UnknownFact
from .verdict import CheckerConclusion, CheckerReport, CounterexampleTrace, Verdict


class CertificateModule(StrictModel):
    # path 用于解释和重新定位同一模块。
    path: str
    # sha256 才是证书绑定模块内容的依据。
    sha256: str
    # role 区分 executable、interpreter 和 shared library。
    role: str


class CertificateScope(StrictModel):
    # executable_sha256 绑定主程序内容；路径变化不改变这个身份。
    executable_sha256: str
    # library_sha256 保留旧证书的紧凑 hash 列表。
    library_sha256: tuple[str, ...]
    # modules 同时保存路径、角色和 hash，便于 stale 检查解释差异。
    modules: tuple[CertificateModule, ...] = ()
    # dbt_contract_version/dbt_revision 固定实际 lowering，而非抽象 RVWMO。
    dbt_contract_version: str
    dbt_revision: str
    # function effect 契约会删除 opaque call，因此版本和内容 hash 都必须进入 scope。
    function_effect_contract_version: str | None = None
    function_effect_contract_sha256: str | None = None
    # argv 和 thread bounds 限定证书适用的执行范围。
    argv: tuple[str, ...] = ()
    thread_count_min: int | None = None
    thread_count_max: int | None = None
    # analysis_config_sha256 绑定环境、checker bounds 和分析选项。
    analysis_config_sha256: str | None = None


class CertificateCoverage(StrictModel):
    # modules/functions/indirect_sites 记录二进制恢复覆盖面。
    modules: int = 0
    functions: int = 0
    indirect_sites: int = 0
    incomplete_indirect_sites: int = 0
    # function_ids/indirect_site_ids 让计数可以回查到具体 binary PC。
    function_ids: tuple[str, ...] = ()
    indirect_site_ids: tuple[str, ...] = ()
    incomplete_indirect_site_ids: tuple[str, ...] = ()
    # thread_roles/unknown_thread_entries 记录线程入口是否闭合。
    thread_roles: int = 0
    unknown_thread_entries: int = 0
    # thread_role_ids 保存证书实际覆盖的静态线程类。
    thread_role_ids: tuple[str, ...] = ()
    # memory_events/shared_events 记录剪枝前后规模。
    memory_events: int = 0
    shared_events: int = 0
    unknown_memory_effects: int = 0
    # memory/shared/unknown event IDs 固定实际送入各层的事件集合。
    memory_event_ids: tuple[str, ...] = ()
    shared_event_ids: tuple[str, ...] = ()
    unknown_memory_effect_ids: tuple[str, ...] = ()
    # shared_objects/unknown_shared_objects 记录地址分类闭合程度。
    shared_objects: int = 0
    unknown_shared_objects: int = 0
    # shared object IDs 让 Unknown 地址和剪枝范围可逐项审计。
    shared_object_ids: tuple[str, ...] = ()
    unknown_shared_object_ids: tuple[str, ...] = ()
    # pruning_counts 按 ProofReason 保存移除数量。
    pruning_counts: dict[str, int] = Field(default_factory=dict)


class PortabilityCertificate(StrictModel):
    # schema_version 防止旧证书被新 verifier 静默接受。
    schema_version: int = 1
    # verdict 只能由 proof/verifier.py 根据完整门禁创建。
    verdict: Verdict
    # scope 绑定全部 binary、DBT 和执行参数。
    scope: CertificateScope
    # coverage 让结论的分析边界可审计。
    coverage: CertificateCoverage
    # checker 保存 bounded/unsupported/timeout 的真实结果。
    checker: CheckerReport
    # proof_objects 解释结构性剪枝；不能只保存计数。
    proof_objects: tuple[ProofObject, ...] = ()
    # relevant_unknowns 非空时 verdict 只能是 UNKNOWN。
    relevant_unknowns: tuple[UnknownFact, ...] = ()
    # counterexample 只随 COUNTEREXAMPLE 出现。
    counterexample: CounterexampleTrace | None = None

    @model_validator(mode="after")
    def enforce_verdict_payload(self) -> "PortabilityCertificate":
        if self.verdict == Verdict.SAFE:
            if self.relevant_unknowns:
                raise ValueError("SAFE certificate cannot contain relevant Unknowns")
            if self.counterexample is not None:
                raise ValueError("SAFE certificate cannot contain a counterexample")
            if (
                self.checker.conclusion != CheckerConclusion.STRUCTURAL_SAFE
                or self.checker.bounded
            ):
                raise ValueError("SAFE requires an unbounded structural proof")
        elif self.verdict == Verdict.COUNTEREXAMPLE:
            if self.counterexample is None:
                raise ValueError("COUNTEREXAMPLE requires a trace")
            if self.relevant_unknowns:
                raise ValueError("COUNTEREXAMPLE cannot contain relevant Unknowns")
            if self.checker.conclusion != CheckerConclusion.TARGET_ONLY:
                raise ValueError("COUNTEREXAMPLE requires a target-only checker result")
        elif self.counterexample is not None:
            raise ValueError("UNKNOWN certificate cannot contain a counterexample")
        elif self.checker.conclusion in {
            CheckerConclusion.STRUCTURAL_SAFE,
            CheckerConclusion.TARGET_ONLY,
        }:
            raise ValueError("UNKNOWN cannot discard a conclusive checker result")
        return self
