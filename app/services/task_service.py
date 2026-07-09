from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.models import Judgment, JudgmentTask
from app.services.intellens_service import IntellensService
from app.services.wfy_service import WfyService
from app.standards import (
    BASES,
    CATEGORY_NEW_CODES,
    CATEGORY_V8_CODES,
    CATEGORY_V9_CODES,
    GENERATION_METHODS,
    MALICIOUS_STAMPS,
    STATUSES,
)


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
REPORT_URL_RE = re.compile(r"https?://[^\s\"'<>，；、（）()\\\\]+")
REPORT_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
TRAFFIC_TYPES = {"http", "dns", "tls", "smtp", "ftp", "irc", "hex"}
SAMPLE_BEHAVIOR_DETAIL_FIELDS = {
    "file_name",
    "file_size",
    "file_type",
    "platform",
    "persistence_mechanism",
    "files_written",
    "processes_tree",
    "tcp_connections",
    "http_requests",
    "behavior_description",
}


@dataclass(frozen=True)
class ParsedIoc:
    raw: str
    host: str
    port: int
    uri: str | None
    protocol: str | None
    ioc_type: str


class ProcessedTaskStore:
    def __init__(self, path: Path):
        self.path = path
        self._keys = self._load()

    def _load(self) -> set[str]:
        if not self.path.exists():
            return set()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return set()
        if not isinstance(data, list):
            return set()
        return {str(item) for item in data if item}

    def contains(self, key: str) -> bool:
        return key in self._keys

    def add(self, key: str) -> None:
        if not key:
            return
        self._keys.add(key)
        self.save()

    def remove(self, key: str) -> None:
        self._keys.discard(key)
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(sorted(self._keys), ensure_ascii=False, indent=2), encoding="utf-8")


class TaskService:
    def __init__(self, intellens_service: IntellensService | None = None, wfy_service: WfyService | None = None):
        self.intellens_service = intellens_service or IntellensService()
        self.wfy_service = wfy_service or WfyService()

    def judge(self, task: JudgmentTask) -> Judgment:
        intel = self.intellens_service.judge_one(task.ioc)
        wfy_fields = self.wfy_service.result_fields_for_ioc(task.ioc)
        judge = wfy_fields.get("judge", "")
        return Judgment(
            ops=ops_from_wfy_judge(judge),
            confidence=wfy_fields.get("confidence"),
            risk_level=wfy_fields.get("risk_level"),
            malicious_stamp="",
            status=wfy_fields.get("status", ""),
            base=wfy_fields.get("base", ""),
            generation_method="",
            category_v8=wfy_fields.get("category_v8"),
            category_v9=wfy_fields.get("category_v9"),
            category_new=wfy_fields.get("category_new"),
            tpd=wfy_fields.get("tpd"),
            first_seen=wfy_fields.get("first_seen", ""),
            evidence=intel.evidence,
            control_type="",
            file_hash=[],
            last_seen="",
            created_time=None,
            modified_time=None,
            campaign=None,
            malicious_family=[],
            platform=[],
            tags=[],
            ttps=[],
            scene=wfy_fields.get("scene"),
            whois=wfy_fields.get("whois"),
            icp=wfy_fields.get("icp"),
            dns=wfy_fields.get("dns"),
            open_port=wfy_fields.get("open_port"),
            geo=wfy_fields.get("geo", []),
            dynamic_domain=wfy_fields.get("dynamic_domain"),
            certificate=wfy_fields.get("certificate"),
        )

    def build_result_payload(self, task: JudgmentTask, judgment: Judgment) -> dict[str, Any]:
        parsed = parse_ioc(task.ioc)
        return {
            "id": task.id,
            "ops": judgment.ops,
            "ioc_host": parsed.host,
            "ioc_port": parsed.port,
            "ioc_uri": parsed.uri,
            "protocol": parsed.protocol,
            "ioc_type": parsed.ioc_type,
            "malicious_stamp": judgment.malicious_stamp,
            "status": judgment.status,
            "base": judgment.base,
            "generation_method": judgment.generation_method,
            "tpd": judgment.tpd,
            "category_v8": judgment.category_v8,
            "category_v9": judgment.category_v9,
            "category_new": judgment.category_new,
            "first_seen": judgment.first_seen,
            "confidence": judgment.confidence,
            "risk_level": judgment.risk_level,
            "control_type": judgment.control_type,
            "file_hash": judgment.file_hash,
            "last_seen": judgment.last_seen,
            "created_time": judgment.created_time,
            "modified_time": judgment.modified_time,
            "campaign": judgment.campaign,
            "malicious_family": judgment.malicious_family,
            "platform": judgment.platform,
            "tags": judgment.tags,
            "ttps": judgment.ttps,
            "evidence": judgment.evidence,
            "scene": judgment.scene,
            "whois": judgment.whois,
            "icp": judgment.icp,
            "dns": judgment.dns,
            "open_port": judgment.open_port,
            "geo": judgment.geo,
            "dynamic_domain": judgment.dynamic_domain,
            "certificate": judgment.certificate,
        }

    def validate_result_payload(self, payload: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        required_fields = (
            "id",
            "ops",
            "ioc_host",
            "ioc_port",
            "ioc_uri",
            "protocol",
            "ioc_type",
        )
        for field in required_fields:
            if field not in payload:
                errors.append(f"missing field: {field}")

        if str(payload.get("id", "")).isdigit() is False:
            errors.append("id must be numeric string")
        if payload.get("ops") not in {"+", "-"}:
            errors.append("ops must be + or -")
        if payload.get("ioc_type") not in {"ip", "domain", "url"}:
            errors.append("ioc_type must be ip/domain/url")
        if payload.get("ioc_type") == "url":
            if not payload.get("ioc_uri"):
                errors.append("ioc_uri is required for url IOC")
            if payload.get("protocol") not in {"http", "https"}:
                errors.append("protocol must be http/https for url IOC")
        if not isinstance(payload.get("ioc_port"), int) or payload.get("ioc_port", -1) < 0:
            errors.append("ioc_port must be non-negative int")
        if has_value(payload.get("malicious_stamp")) and payload.get("malicious_stamp") not in MALICIOUS_STAMPS:
            errors.append("malicious_stamp enum invalid")
        if has_value(payload.get("status")) and payload.get("status") not in STATUSES:
            errors.append("status enum invalid")
        if has_value(payload.get("base")) and payload.get("base") not in BASES:
            errors.append("base enum invalid")
        if has_value(payload.get("generation_method")) and payload.get("generation_method") not in GENERATION_METHODS:
            errors.append("generation_method enum invalid")
        for field in ("category_v8", "category_v9", "category_new", "confidence", "risk_level"):
            if has_value(payload.get(field)) and not isinstance(payload.get(field), int):
                errors.append(f"{field} must be int")
        if has_value(payload.get("confidence")) and payload.get("confidence") not in {1, 2, 3}:
            errors.append("confidence must be 1/2/3")
        if has_value(payload.get("risk_level")) and payload.get("risk_level") not in {1, 2, 3}:
            errors.append("risk_level must be 1/2/3")
        if isinstance(payload.get("category_v8"), int) and payload.get("category_v8") not in CATEGORY_V8_CODES:
            errors.append("category_v8 enum invalid")
        if isinstance(payload.get("category_v9"), int) and payload.get("category_v9") not in CATEGORY_V9_CODES:
            errors.append("category_v9 enum invalid")
        if isinstance(payload.get("category_new"), int) and payload.get("category_new") not in CATEGORY_NEW_CODES:
            errors.append("category_new enum invalid")
        for field in ("first_seen", "last_seen", "created_time", "modified_time"):
            value = payload.get(field)
            if value and not is_utc_iso8601(str(value)):
                errors.append(f"{field} must be UTC ISO 8601")

        evidence = payload.get("evidence")
        if not has_value(evidence):
            return errors
        if not isinstance(evidence, dict):
            errors.append("evidence must be object")
            return errors
        errors.extend(validate_evidence(evidence, str(payload.get("base", "")), int(payload.get("category_new") or 0)))
        return errors

    def result_key(self, task: JudgmentTask, timestamp: str | None = None) -> str:
        stamp = timestamp or timestamp_millis()
        date = task.date or datetime.now().strftime("%Y%m%d")
        return f"{date}/{task.id}/assessment_results_{task.id}_{stamp}.json"

    def write_result(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def is_overdue(self, task: JudgmentTask, deadline_seconds: int) -> bool:
        if task.received_at is None:
            return False
        received_at = task.received_at
        if received_at.tzinfo is None:
            received_at = received_at.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - received_at.astimezone(timezone.utc)).total_seconds() > deadline_seconds


def parse_ioc(value: object) -> ParsedIoc:
    text = "" if value is None else str(value).strip()
    parsed = urlparse(text)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return ParsedIoc(
            raw=text,
            host=parsed.hostname or parsed.netloc,
            port=parsed.port or (443 if parsed.scheme == "https" else 80),
            uri=parsed.path or "/",
            protocol=parsed.scheme,
            ioc_type="url",
        )

    host, sep, port_text = text.rpartition(":")
    if sep and host and port_text.isdigit():
        port = int(port_text)
        if 1 <= port <= 65535:
            try:
                ipaddress.ip_address(host)
                return ParsedIoc(text, host, port, None, None, "ip")
            except ValueError:
                if DOMAIN_RE.fullmatch(host):
                    return ParsedIoc(text, host, port, None, None, "domain")

    try:
        ipaddress.ip_address(text)
        return ParsedIoc(text, text, 0, None, None, "ip")
    except ValueError:
        pass

    if DOMAIN_RE.fullmatch(text):
        return ParsedIoc(text, text, 0, None, None, "domain")
    return ParsedIoc(text, text, 0, None, None, "unknown")


def ops_from_wfy_judge(judge: str) -> str:
    return "+" if str(judge or "").strip().lower() == "black" else "-"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def timestamp_millis() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")[:-3]


def is_utc_iso8601(value: str) -> bool:
    if not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def validate_evidence(evidence: dict[str, Any], base: str, category_new: int) -> list[str]:
    errors: list[str] = []
    evidence_fields = (
        "sample_behavior",
        "source_links",
        "related_vulnerabilities",
        "traffic_fragments",
        "phishing_details",
        "other_evidence",
        "manual_analysis",
    )
    if not any(has_value(evidence.get(field)) for field in evidence_fields):
        return errors
    if "manual_analysis" in evidence and evidence.get("manual_analysis") != 1:
        errors.append("manual_analysis must be 1 when present")
        return errors

    sample_behavior = evidence.get("sample_behavior")
    if isinstance(sample_behavior, dict):
        if not (has_value(sample_behavior.get("hash_md5")) or has_value(sample_behavior.get("hash_sha256"))):
            errors.append("sample_behavior requires hash_md5 or hash_sha256")
        if has_value(sample_behavior.get("behavior_description")) and len(str(sample_behavior.get("behavior_description"))) > 1000:
            errors.append("sample_behavior.behavior_description must be <= 1000 characters")

    source_links = evidence.get("source_links")
    if has_value(source_links):
        links = source_links if isinstance(source_links, list) else [source_links]
        if not any(is_valid_report_url(clean_report_url(str(link))) for link in links):
            errors.append("source_links must contain valid http/https URL")

    traffic = evidence.get("traffic_fragments")
    if isinstance(traffic, dict):
        if traffic.get("traffic_type") not in TRAFFIC_TYPES:
            errors.append("traffic_fragments.traffic_type enum invalid")
        if not has_value(traffic.get("traffic_pattern")):
            errors.append("traffic_fragments.traffic_pattern is required")
        if not has_value(traffic.get("description")):
            errors.append("traffic_fragments.description is required")
        if has_value(traffic.get("traffic_pattern")) and len(str(traffic.get("traffic_pattern"))) > 1024:
            errors.append("traffic_fragments.traffic_pattern must be <= 1024 characters")
        if has_value(traffic.get("description")) and len(str(traffic.get("description"))) > 1000:
            errors.append("traffic_fragments.description must be <= 1000 characters")

    phishing = evidence.get("phishing_details")
    if isinstance(phishing, dict):
        if not (
            has_value(phishing.get("brand"))
            or has_value(phishing.get("target_system"))
            or has_value(phishing.get("website_title"))
        ):
            errors.append("phishing_details requires brand/target_system/website_title")
        if not has_value(phishing.get("behavior_description")):
            errors.append("phishing_details.behavior_description is required")

    other_evidence = evidence.get("other_evidence")
    if isinstance(other_evidence, str) and len(other_evidence) > 2048:
        errors.append("other_evidence must be <= 2048 characters")
    if isinstance(other_evidence, dict):
        if has_value(other_evidence.get("parent_intelligence")) and not has_value(other_evidence.get("parent_evidence")):
            errors.append("other_evidence.parent_evidence is required when parent_intelligence is present")
        if has_value(other_evidence.get("parent_intelligence")) and not has_value(other_evidence.get("pivoting_feature")):
            errors.append("other_evidence.pivoting_feature is required when parent_intelligence is present")
    return errors


def clean_report_url(url: str) -> str:
    text = str(url or "").strip().strip("\"'").rstrip(".,;，；。")
    if not text:
        return ""
    for marker in ("@Version:", "@version:", "@VERSION:", "@"):
        if marker in text:
            text = text.split(marker, 1)[0]
            break
    if "#" in text:
        text = text.split("#", 1)[0]
    return text.rstrip(".,;，；。")


def is_valid_report_url(url: str) -> bool:
    if not url or re.search(r"\s|\\", url):
        return False
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    if parsed.username or parsed.password:
        return False
    try:
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False
    except ValueError:
        return False
    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(REPORT_HOST_RE.fullmatch(host))
