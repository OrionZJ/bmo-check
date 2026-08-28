from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    """Reject undeclared fields so stale facts cannot silently enter a proof."""

    model_config = ConfigDict(extra="forbid", frozen=True)
