from __future__ import annotations

import time
from typing import Any

from app.intellens.config import (
    REQUEST_TIMEOUT,
    WFY_API_URL,
    WFY_HEADERS,
    WFY_RETRIES,
    WFY_RETRY_SLEEP_SECONDS,
)
from app.intellens.utils import get_thread_session, json_utf8_body, normalize_cell, safe_int, safe_json_response


class WfyService:
    """Secondlens-owned WFY v2 field adapter.

    This currently mirrors IntelLens WFY v2 response parsing. Keep IntelLens pipeline on v2;
    replace this adapter when secondlens WFY-backed fields should move to WFY v3.
    """

    def result_fields_for_ioc(self, ioc: str) -> dict[str, Any]:
        info = self.query_one_v2(ioc)
        return self.result_fields_from_wfy_info(info)

    def status_from_wfy_info(self, info: dict[str, Any]) -> str:
        raw_status = normalize_cell(info.get("status"))
        return map_wfy_status_to_rd(raw_status)

    def result_fields_from_wfy_info(self, info: dict[str, Any]) -> dict[str, Any]:
        return {
            "judge": normalize_cell(info.get("judge")).lower(),
            "status": self.status_from_wfy_info(info),
            "base": normalize_cell(info.get("base")),
            "tpd": normalize_tpd(info.get("tpd")),
            "category_v8": first_int(info.get("category_v8")),
            "category_v9": first_int(info.get("category_v9")),
            "category_new": first_int(info.get("category_new")),
            "first_seen": normalize_cell(info.get("first_seen")),
            "confidence": optional_int(info.get("confidence")),
            "risk_level": optional_int(info.get("risk_level")),
            "control_type": "",
            "file_hash": [],
            "last_seen": "",
            "created_time": None,
            "modified_time": None,
            "campaign": None,
            "malicious_family": [],
            "platform": [],
            "tags": [],
            "ttps": [],
            "scene": optional_int(info.get("scene")),
            "whois": dict_or_none(info.get("whois")),
            "icp": info.get("icp"),
            "dns": text_list_or_none(info.get("dns")),
            "open_port": int_list_or_none(info.get("open_port")),
            "geo": text_list(info.get("geo")),
            "dynamic_domain": optional_bool(info.get("dynamic_domain")),
            "certificate": optional_text(info.get("certificate")),
        }

    def query_one_v2(self, ioc: str) -> dict[str, Any]:
        if not ioc:
            return {}
        _, parsed, _ = query_wfy_v2_batch([ioc])
        return parsed.get(ioc, {})


def query_wfy_v2_batch(batch: list[str]) -> tuple[list[str], dict[str, dict[str, Any]], str]:
    last_error = ""
    max_attempts = WFY_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        try:
            session = get_thread_session()
            resp = session.post(
                WFY_API_URL,
                headers=WFY_HEADERS,
                data=json_utf8_body(batch),
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 429 and attempt < max_attempts:
                retry_after = safe_int(resp.headers.get("Retry-After"), 0)
                sleep_seconds = retry_after if retry_after > 0 else WFY_RETRY_SLEEP_SECONDS * (2 ** (attempt - 1))
                time.sleep(sleep_seconds)
                continue
            resp.raise_for_status()
            data = safe_json_response(resp)
            return batch, parse_wfy_v2_response(batch, data), ""
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_attempts:
                time.sleep(WFY_RETRY_SLEEP_SECONDS * (2 ** (attempt - 1)))
                continue
            return batch, {ioc: {"query_error": last_error, "judge": ""} for ioc in batch}, last_error
    last_error = last_error or "wfy query failed"
    return batch, {ioc: {"query_error": last_error, "judge": ""} for ioc in batch}, last_error


def parse_wfy_v2_response(batch: list[str], data: Any) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    if isinstance(data, dict):
        candidate = data.get("data")
        if isinstance(candidate, dict):
            for ioc in batch:
                value = candidate.get(ioc, candidate.get("query_ioc", []))
                parsed[ioc] = normalize_wfy_v2_value(ioc, value)
            return parsed

    for ioc in batch:
        parsed.setdefault(ioc, {})
    return parsed


def normalize_wfy_v2_value(query_ioc: str, value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and normalize_cell(item.get("ioc")) == query_ioc:
                return item
    return {}


def map_wfy_status_to_rd(status: str) -> str:
    normalized = normalize_cell(status).upper()
    status_map = {
        "ACTIVE": "active",
        "UNKNOWN": "unknown",
        "OVER": "inactive",
        "SINKHOLE": "sinkhole",
        "": "",
    }
    return status_map.get(normalized, normalized.lower())


def first_int(value: Any) -> int | None:
    if isinstance(value, list):
        for item in value:
            parsed = optional_int(item)
            if parsed is not None:
                return parsed
        return None
    return optional_int(value)


def optional_int(value: Any) -> int | None:
    text = normalize_cell(value)
    if not text:
        return None
    try:
        return int(float(text))
    except ValueError:
        return None


def optional_text(value: Any) -> str | None:
    text = normalize_cell(value)
    return text or None


def normalize_tpd(value: Any) -> bool | None:
    text = normalize_cell(value).lower()
    if not text:
        return None
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    return None


def optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = normalize_cell(value).lower()
    if not text:
        return None
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    return None


def text_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in (normalize_cell(item) for item in value) if item]
    if isinstance(value, tuple | set):
        return [item for item in (normalize_cell(item) for item in value) if item]
    text = normalize_cell(value)
    return [text] if text else []


def text_list_or_none(value: Any) -> list[str] | None:
    values = text_list(value)
    return values or None


def int_list_or_none(value: Any) -> list[int] | None:
    if value is None:
        return None
    raw_values = value if isinstance(value, list) else [value]
    values: list[int] = []
    for item in raw_values:
        parsed = optional_int(item)
        if parsed is not None:
            values.append(parsed)
    return values or None


def dict_or_none(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None

