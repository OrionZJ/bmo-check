from __future__ import annotations

import hashlib
import json
from pathlib import Path

from bmo_check_dynamic.model import (
    PpoCertificateCacheArtifact,
    PpoCertificateCacheKey,
    PpoCertificateCacheLoad,
    PpoGraphBinding,
    PpoReductionCertificate,
    PpoReductionReplay,
)

from .ppo_reduction import PpoGraphInput, ppo_certificate_digest, replay_ppo_reduction


REDUCTION_ALGORITHM_VERSION = "ppo-reduction-v1-witness-index-v1"


def ppo_certificate_cache_key(
    graph: PpoGraphInput,
    certificate: PpoReductionCertificate,
    *,
    trace_digest: str,
    window_digest: str,
    dbt_contract_digest: str,
) -> PpoCertificateCacheKey:
    """建立完整缓存键；缺少任一外部绑定时调用者应传显式空值并拒绝复用。"""

    required_pair_inventory_digest = _digest_json(
        {
            "source": _inventory_payload(certificate.source.required_reachability_pairs),
            "target": _inventory_payload(certificate.target.required_reachability_pairs),
        }
    )
    return PpoCertificateCacheKey(
        trace_digest=trace_digest,
        window_digest=window_digest,
        event_set_digest=_event_set_digest(graph),
        source_ppo_digest=_binding_digest(certificate.source_binding),
        target_ppo_digest=_binding_digest(certificate.target_binding),
        dbt_contract_digest=dbt_contract_digest,
        reduction_algorithm_version=REDUCTION_ALGORITHM_VERSION,
        required_pair_inventory_digest=required_pair_inventory_digest,
        ppo_contract_digest=certificate.contract.contract_digest,
    )


def save_ppo_certificate_cache(
    path: Path,
    graph: PpoGraphInput,
    certificate: PpoReductionCertificate,
    replay: PpoReductionReplay,
    *,
    trace_digest: str,
    window_digest: str,
    dbt_contract_digest: str,
) -> PpoCertificateCacheKey:
    """写入确定性缓存副本；写入前不改变 certificate 本身。"""

    key = ppo_certificate_cache_key(
        graph,
        certificate,
        trace_digest=trace_digest,
        window_digest=window_digest,
        dbt_contract_digest=dbt_contract_digest,
    )
    payload = {
        "cache_key": key.model_dump(mode="json"),
        "certificate": certificate.model_dump(mode="json"),
        "replay": replay.model_dump(mode="json"),
    }
    artifact = PpoCertificateCacheArtifact(
        cache_key=key,
        certificate=certificate,
        replay=replay,
        artifact_digest=_digest_json(payload),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
    return key


def load_ppo_certificate_cache(
    path: Path,
    graph: PpoGraphInput,
    *,
    trace_digest: str,
    window_digest: str,
    dbt_contract_digest: str,
) -> PpoCertificateCacheLoad:
    """读取缓存并用当前 graph 独立 replay；任何绑定不匹配都不能命中。"""

    if not path.is_file():
        return PpoCertificateCacheLoad(status="miss", reasons=("cache file does not exist",))
    try:
        artifact = PpoCertificateCacheArtifact.model_validate_json(
            path.read_text(encoding="utf-8")
        )
    except Exception as error:
        return PpoCertificateCacheLoad(
            status="corrupt", reasons=(f"cache schema or JSON is invalid: {error}",)
        )

    expected_key = ppo_certificate_cache_key(
        graph,
        artifact.certificate,
        trace_digest=trace_digest,
        window_digest=window_digest,
        dbt_contract_digest=dbt_contract_digest,
    )
    if artifact.cache_key != expected_key:
        return PpoCertificateCacheLoad(
            status="stale", reasons=("cache key does not match current inputs",)
        )
    expected_artifact_digest = _digest_json(
        {
            "cache_key": artifact.cache_key.model_dump(mode="json"),
            "certificate": artifact.certificate.model_dump(mode="json"),
            "replay": artifact.replay.model_dump(mode="json"),
        }
    )
    if artifact.artifact_digest != expected_artifact_digest:
        return PpoCertificateCacheLoad(
            status="corrupt", reasons=("cache artifact digest does not match contents",)
        )
    if ppo_certificate_digest(artifact.certificate) != artifact.certificate.proof_digest:
        return PpoCertificateCacheLoad(
            status="corrupt", reasons=("cached certificate proof digest is invalid",)
        )

    replay = replay_ppo_reduction(graph, artifact.certificate)
    if replay != artifact.replay:
        return PpoCertificateCacheLoad(
            status="corrupt", reasons=("independent replay differs from cached replay",)
        )
    return PpoCertificateCacheLoad(
        status="hit",
        certificate=artifact.certificate,
        replay=replay,
    )


def _inventory_payload(inventory: object) -> object:
    return getattr(inventory, "model_dump")(mode="json")


def _binding_digest(binding: PpoGraphBinding) -> str:
    return binding.edge_digest


def _event_set_digest(graph: PpoGraphInput) -> str:
    return _digest_json(
        [
            {
                "thread_id": event.thread_id,
                "sequence": event.sequence,
                "ticket": event.ticket,
                "pc": event.pc,
                "kind": int(event.kind),
                "address": event.address,
                "size": event.size,
                "value": event.value,
                "flags": int(event.flags),
                "aux": event.aux,
                "operand_index": event.operand_index,
            }
            for event in graph.events
        ]
    )


def _digest_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "REDUCTION_ALGORITHM_VERSION",
    "ppo_certificate_cache_key",
    "save_ppo_certificate_cache",
    "load_ppo_certificate_cache",
]
