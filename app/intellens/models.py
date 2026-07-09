"""IntelLens 数据模型：各外部接口返回结构 + 单行研判结果。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.intellens import config
from app.intellens.utils import normalize_cell


@dataclass
class HashInfo:
    query_hash: str = ""
    risk: str = ""
    file_size: str = ""
    file_type: str = ""
    first_seen_time: str = ""
    operating_system: str = ""
    malware_family: str = ""
    virus_name: str = ""
    threat_type_name: str = ""

    @property
    def other_file_feature(self) -> str:
        values = [
            normalize_cell(self.malware_family),
            normalize_cell(self.virus_name),
            normalize_cell(self.threat_type_name),
        ]
        return " ".join(dict.fromkeys(value for value in values if value))


@dataclass
class XmonInfo:
    ioc_search: str = ""
    disable: str = ""
    status: str = ""
    ref_sample: Any = ""
    report_links: Any = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_disabled(self) -> bool:
        text = str(self.disable).strip().lower()
        return text in {"1", "true", "yes", "disabled"}


@dataclass
class WdInfo:
    ioc: str = ""
    level: int | None = None
    sub_level: int | None = None
    malicious: bool = False
    has_snapshot: bool = False
    snapshot_topic: str = ""
    snapshot_title: str = ""
    snapshot_content: str = ""
    query_error: str = ""


@dataclass
class AiInfo:
    ioc: str = ""
    key_evidence: list[str] = field(default_factory=list)
    summary: str = ""
    query_error: str = ""


@dataclass
class ExternalIocInfo:
    ioc: str = ""
    hit_rule: str = ""
    query_error: str = ""

    @property
    def malicious(self) -> bool:
        return bool(self.hit_rule)


@dataclass
class RowDecision:
    ioc: str
    result_ioc: str
    port: str
    vendor: str = config.VENDOR
    out_date: str = ""
    k01_result: str = ""
    alive_status: str = ""
    file_hash: str = ""
    file_size: str = ""
    file_type: str = ""
    operating_system: str = ""
    create_time: str = ""
    other_file_feature: str = ""
    info_add: str = ""
    false_positive_reason: str = ""
    owner: str = "unknown"
    solvable: str = "否"
    solution: str = "无更多依据关联"
    rule_hit: str = "no_more_evidence"
    hit_rule: str = ""
    abnormal_input: bool = False
