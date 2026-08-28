from __future__ import annotations

from .common import StrictModel


class CertificateScope(StrictModel):
    executable_sha256: str
    library_sha256: tuple[str, ...]
    dbt_contract_version: str
    dbt_revision: str
    argv: tuple[str, ...] = ()
    thread_count_min: int | None = None
    thread_count_max: int | None = None
    analysis_config_sha256: str | None = None
