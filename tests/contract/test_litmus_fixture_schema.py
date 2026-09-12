from __future__ import annotations

import pytest

from bmo_check_evaluation.litmus import (
    FixtureEventKind,
    HerdOutcome,
    LitmusFixtureError,
    LitmusManifest,
    load_manifest,
)


HASH = "a" * 64


def _payload() -> dict[str, object]:
    return {
        "schema": 1,
        "corpus_name": "local-litmus",
        "corpus_revision": "rev-1",
        "cases": [
            {
                "case_id": "case-1",
                "binding": {
                    "source_litmus": "tests/non-mixed-size/BASIC_2_THREAD/SB.litmus",
                    "source_sha256": HASH,
                    "elf_relative_path": "elf-tests/BASIC_2_THREAD/SB/SB.exe",
                    "elf_sha256": HASH,
                    "corpus_revision": "rev-1",
                    "build_recipe": "litmus7 -o <out> <source> && make -C <out>",
                },
                "critical_events": [
                    {
                        "label": "t0:w-x",
                        "thread": 0,
                        "ordinal": 0,
                        "kind": "Store",
                        "object_label": "x",
                        "width": 8,
                        "thread_entry_pc": 4096,
                    },
                    {
                        "label": "t1:r-x",
                        "thread": 1,
                        "ordinal": 0,
                        "kind": "Load",
                        "object_label": "x",
                        "width": 8,
                    },
                ],
                "program_order": [],
                "executions": [
                    {
                        "assignment_id": "initial",
                        "read_from": [{"load": "t1:r-x"}],
                    }
                ],
                "oracle": {
                    "herd_version": "herd7-test",
                    "source_model": "x86.cat",
                    "target_model": "riscv.cat",
                    "source_outcome": "Allowed",
                    "target_outcome": "Allowed",
                    "source_input_sha256": HASH,
                    "target_input_sha256": HASH,
                    "elf_sha256": HASH,
                    "contract_version": "dbt6-mo-off-v2",
                    "contract_sha256": HASH,
                    "raw_output_sha256": HASH,
                },
            }
        ],
    }


def test_manifest_round_trip_and_enum_types(tmp_path) -> None:
    path = tmp_path / "manifest.yaml"
    import yaml

    path.write_text(yaml.safe_dump(_payload()), encoding="utf-8")
    manifest = load_manifest(path)
    assert isinstance(manifest, LitmusManifest)
    assert manifest.schema_version == 1
    assert manifest.cases[0].critical_events[0].kind is FixtureEventKind.STORE
    assert manifest.cases[0].oracle.source_outcome is HerdOutcome.ALLOWED


@pytest.mark.parametrize(
    "mutator",
    [
        lambda payload: payload["cases"][0]["binding"].update({"elf_sha256": "bad"}),
        lambda payload: payload["cases"][0]["binding"].update({"elf_relative_path": "../SB.exe"}),
        lambda payload: payload["cases"][0]["oracle"].update({"elf_sha256": "b" * 64}),
        lambda payload: payload["cases"][0]["executions"].clear(),
    ],
)
def test_invalid_manifest_is_rejected(tmp_path, mutator) -> None:
    import copy
    import yaml

    payload = copy.deepcopy(_payload())
    mutator(payload)
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(LitmusFixtureError):
        load_manifest(path)


def test_duplicate_case_ids_and_unknown_relation_labels_are_rejected() -> None:
    payload = _payload()
    payload["cases"].append(payload["cases"][0])
    with pytest.raises(ValueError, match="case_id"):
        LitmusManifest.model_validate(payload)

    payload = _payload()
    payload["cases"][0]["program_order"] = [
        {"source": "missing", "target": "t1:r-x"}
    ]
    with pytest.raises(ValueError, match="unknown event"):
        LitmusManifest.model_validate(payload)
