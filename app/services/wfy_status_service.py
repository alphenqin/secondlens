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


class WfyStatusService:
    """Secondlens-owned WFY status adapter.

    This currently mirrors IntelLens WFY v2 response parsing. Keep IntelLens pipeline on v2;
    replace this adapter when secondlens status should move to WFY v3.
    """

    def status_for_ioc(self, ioc: str) -> str:
        info = self.query_one_v2(ioc)
        return self.status_from_wfy_info(info)

    def status_from_wfy_info(self, info: dict[str, Any]) -> str:
        raw_status = normalize_cell(info.get("status"))
        return map_wfy_status_to_rd(raw_status)

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
