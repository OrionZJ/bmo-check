from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BinaryFingerprint(StrictModel):
    path: str
    sha256: str
    build_id: str | None = None


class TraceManifest(StrictModel):
    schema_version: str = "1.0"
    trace_id: str
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    platform: str
    architecture: str = "x86_64"
    command: tuple[str, ...]
    working_directory: str
    environment: dict[str, str] = Field(default_factory=dict)
    executable: BinaryFingerprint
    libraries: tuple[BinaryFingerprint, ...] = ()
    dynamorio_version: str = "unknown"
    client_version: str = "0.1"
    complete: bool = False
    exit_code: int | None = None
    dropped_events: int = 0
    dropped_by_reason: dict[str, int] = Field(default_factory=dict)
    control_flow_closed: bool = False
    limitations: tuple[str, ...] = ()

    @classmethod
    def load(cls, path: Path) -> "TraceManifest":
        return cls.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, path: Path) -> None:
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")
