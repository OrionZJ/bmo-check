from __future__ import annotations

from pathlib import Path

import yaml

from bmo_check_static.model import EvaluationSuite


def load_evaluation_suite(path: Path) -> EvaluationSuite:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ValueError(f"cannot load evaluation suite {path}: {error}") from error
    return EvaluationSuite.model_validate(payload)
