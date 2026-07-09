from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AlertMessage:
    id: str
    alertdev_count: int = 0
    alert_count: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "AlertMessage":
        return cls(
            id=str(value.get("id", "")),
            alertdev_count=int(value.get("alertdevCount") or value.get("alertdev_count") or 0),
            alert_count=int(value.get("alertCount") or value.get("alert_count") or 0),
            raw=value,
        )


@dataclass(frozen=True)
class JudgmentTask:
    id: str
    ioc: str
    date: str
    source_key: str = ""
    alerts: tuple[AlertMessage, ...] = ()
    received_at: datetime | None = None

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        date: str = "",
        source_key: str = "",
        alerts: tuple[AlertMessage, ...] = (),
        received_at: datetime | None = None,
    ) -> "JudgmentTask":
        return cls(
            id=str(value.get("id", "")),
            ioc=str(value.get("ioc", "")),
            date=date,
            source_key=source_key,
            alerts=alerts,
            received_at=received_at,
        )


@dataclass(frozen=True)
class Judgment:
    ops: str
    confidence: int | None
    risk_level: int | None
    malicious_stamp: str
    status: str
    base: str
    generation_method: str
    category_v8: int | None
    category_v9: int | None
    category_new: int | None
    tpd: bool | None = None
    first_seen: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    control_type: str = ""
    file_hash: list[str] = field(default_factory=list)
    last_seen: str = ""
    created_time: str | None = None
    modified_time: str | None = None
    campaign: str | None = None
    malicious_family: list[str] = field(default_factory=list)
    platform: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    ttps: list[str] = field(default_factory=list)
    scene: int | None = None
    whois: dict[str, Any] | None = None
    icp: Any = None
    dns: list[str] | None = None
    open_port: list[int] | None = None
    geo: list[str] = field(default_factory=list)
    dynamic_domain: bool | None = None
    certificate: str | None = None


@dataclass(frozen=True)
class ProcessedTask:
    task: JudgmentTask
    key: str
    local_path: Path
    uploaded: bool
    validation_errors: tuple[str, ...] = ()
    overdue: bool = False
