from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.intellens.clients.hash import extract_hashes_from_xmon_info
from app.intellens.decision import clean_report_url, pick_first_report
from app.intellens.models import AiInfo, ExternalIocInfo, HashInfo, RowDecision, WdInfo, XmonInfo
from app.intellens.pipeline import run_decision_pipeline
from app.intellens.utils import normalize_cell


CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass(frozen=True)
class IntelLensJudgment:
    evidence: dict[str, Any] = field(default_factory=dict)


class IntellensService:
    def judge_one(self, ioc: str) -> IntelLensJudgment:
        result = run_decision_pipeline([ioc])
        decision = result.decisions.get(ioc)
        if decision is None:
            return IntelLensJudgment(evidence=empty_evidence())
        return build_judgment_from_pipeline(ioc, decision, result)


def build_judgment_from_pipeline(ioc: str, decision: RowDecision, result: Any) -> IntelLensJudgment:
    return IntelLensJudgment(evidence=build_evidence_from_pipeline(ioc, decision, result))


def empty_evidence() -> dict[str, Any]:
    return {
        "sample_behavior": None,
        "source_links": None,
        "related_vulnerabilities": None,
        "traffic_fragments": None,
        "phishing_details": None,
        "other_evidence": None,
    }


def build_evidence_from_pipeline(ioc: str, decision: RowDecision, result: Any) -> dict[str, Any]:
    xmon_info = result.xmon_map.get(ioc, XmonInfo(ioc_search=ioc))
    ai_info = result.ai_map.get(ioc, AiInfo(ioc=ioc))
    external_info = result.external_ioc_map.get(ioc, ExternalIocInfo(ioc=ioc))
    wd_info = result.wd_map.get(ioc, WdInfo(ioc=ioc))
    evidence = empty_evidence()

    sample_behavior = build_sample_behavior(decision, xmon_info, result.hash_map)
    if sample_behavior:
        evidence["sample_behavior"] = sample_behavior

    source_link = pick_first_report(xmon_info.report_links) or extract_first_url(decision.info_add)
    if source_link:
        evidence["source_links"] = source_link

    cves = extract_cves(decision.info_add, ai_info.summary, " ".join(ai_info.key_evidence))
    if cves:
        evidence["related_vulnerabilities"] = cves

    traffic = build_traffic_fragments(ioc, decision, ai_info, xmon_info)
    if traffic:
        evidence["traffic_fragments"] = traffic

    phishing = build_phishing_details(decision, wd_info, ai_info)
    if phishing:
        evidence["phishing_details"] = phishing

    other = build_other_evidence(decision, external_info, wd_info)
    if other:
        evidence["other_evidence"] = json.dumps(other, ensure_ascii=False, separators=(",", ":"))
    return evidence


def build_sample_behavior(decision: RowDecision, xmon_info: XmonInfo, hash_map: dict[str, HashInfo]) -> dict[str, Any] | None:
    file_hash = normalize_cell(decision.file_hash)
    hash_info = hash_map.get(file_hash, HashInfo(query_hash=file_hash)) if file_hash else HashInfo()
    if not file_hash:
        for ref_hash in extract_hashes_from_xmon_info(xmon_info):
            candidate = hash_map.get(ref_hash, HashInfo(query_hash=ref_hash))
            if normalize_cell(candidate.risk):
                file_hash = ref_hash
                hash_info = candidate
                break
    if not file_hash:
        return None

    sample: dict[str, Any] = {"hash_md5": file_hash if len(file_hash) == 32 else "", "hash_sha256": file_hash if len(file_hash) == 64 else ""}
    if normalize_cell(hash_info.file_size):
        sample["file_size"] = parse_file_size_bytes(hash_info.file_size)
    if normalize_cell(hash_info.file_type):
        sample["file_type"] = hash_info.file_type
    if normalize_cell(hash_info.operating_system):
        sample["platform"] = [hash_info.operating_system]
    behavior_parts = [value for value in (decision.info_add, hash_info.malware_family, hash_info.virus_name, hash_info.threat_type_name) if normalize_cell(value)]
    if behavior_parts:
        sample["behavior_description"] = "；".join(dict.fromkeys(behavior_parts))[:1000]
    return {key: value for key, value in sample.items() if value not in ("", None, [], {})}


def build_traffic_fragments(ioc: str, decision: RowDecision, ai_info: AiInfo, xmon_info: XmonInfo) -> dict[str, str] | None:
    text = "；".join(value for value in [decision.info_add, ai_info.summary, "；".join(ai_info.key_evidence), normalize_cell(xmon_info.raw)] if value)
    if not text:
        return None
    lowered = text.lower()
    traffic_type = ""
    for candidate in ("tls", "dns", "http", "smtp", "ftp", "irc"):
        if candidate in lowered:
            traffic_type = candidate
            break
    if not traffic_type:
        return None
    return {
        "traffic_type": traffic_type,
        "traffic_pattern": summarize_text(text, 1024),
        "description": summarize_text(decision.info_add or ai_info.summary or text, 1000),
    }


def build_phishing_details(decision: RowDecision, wd_info: WdInfo, ai_info: AiInfo) -> dict[str, Any] | None:
    text = "；".join(value for value in (decision.info_add, wd_info.snapshot_title, wd_info.snapshot_content, ai_info.summary) if normalize_cell(value))
    if "钓鱼" not in text and "phish" not in text.lower():
        return None
    return {
        "website_title": [wd_info.snapshot_title] if normalize_cell(wd_info.snapshot_title) else [],
        "behavior_description": summarize_text(text, 1000),
    }


def build_other_evidence(decision: RowDecision, external_info: ExternalIocInfo, wd_info: WdInfo) -> dict[str, Any]:
    data = {
        "hit_rule": normalize_cell(decision.hit_rule),
        "owner": normalize_cell(decision.owner),
        "supplement_info": normalize_cell(decision.info_add),
        "external_hit_rule": normalize_cell(external_info.hit_rule),
        "wd_snapshot_topic": normalize_cell(wd_info.snapshot_topic),
    }
    return {key: value for key, value in data.items() if value}


def map_base(decision: RowDecision) -> str:
    if decision.rule_hit == "black_hash":
        return "sample"
    if decision.rule_hit == "report":
        return "public"
    if decision.rule_hit in {"ai_evidence_chain", "atateam_evidence_chain", "siyubo_evidence_chain"}:
        return "vendor"
    return ""


def extract_first_url(value: str) -> str:
    match = re.search(r"https?://[^\s\"'<>，；、（）()\\\\]+", normalize_cell(value))
    if not match:
        return ""
    return clean_report_url(match.group(0))


def extract_cves(*values: str) -> list[str]:
    cves: list[str] = []
    for value in values:
        cves.extend(match.upper() for match in CVE_RE.findall(normalize_cell(value)))
    return list(dict.fromkeys(cves))


def parse_file_size_bytes(value: str) -> int | None:
    text = normalize_cell(value)
    match = re.search(r"\((\d+) bytes\)", text)
    if match:
        return int(match.group(1))
    if text.isdigit():
        return int(text)
    return None


def summarize_text(value: str, limit: int) -> str:
    return re.sub(r"\s+", " ", normalize_cell(value)).strip()[:limit]
