"""IntelLens xmon 主线索 + tagmon 子线索查询客户端与 XmonInfo 构建。
"""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import quote, urlparse

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import XmonInfo
from app.intellens.decision import build_report_candidates, report_timestamp_from_value


def extract_xmon_rows(resp_json: Any) -> list[dict[str, Any]]:
    if isinstance(resp_json, list):
        return [x for x in resp_json if isinstance(x, dict)]
    if not isinstance(resp_json, dict):
        return []

    for key in ("data", "result", "results", "list"):
        data = resp_json.get(key)
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            return [x for x in data.values() if isinstance(x, dict)]
    return [resp_json]


def has_meaningful_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, dict)):
        return len(value) > 0
    return bool(normalize_cell(value))


def extract_xmon_disable(row: dict[str, Any], raw: dict[str, Any]) -> str:
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    direct = first_not_empty(
        row.get("disable"),
        row.get("Disabled"),
        row.get("disabled"),
        row.get("ioc_disabled"),
        exts.get("disable"),
        exts.get("Disabled"),
        exts.get("disabled"),
        raw.get("disable"),
        raw.get("Disabled"),
    )
    if direct:
        return direct

    tags_info = row.get("tags_info")
    if isinstance(tags_info, list):
        for item in tags_info:
            if isinstance(item, dict):
                disabled = first_not_empty(item.get("disabled"), item.get("disable"), item.get("Disabled"))
                if disabled:
                    return disabled
    return ""


def extract_main_report_link_values(row: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    value = row.get("report_links")
    if has_meaningful_value(value):
        values.append(value)
    return values


def extract_child_report_link_values(row: dict[str, Any]) -> list[Any]:
    values: list[Any] = []
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    value = exts.get("report_link")
    if has_meaningful_value(value):
        values.append(value)
    return values


def collect_xmon_report_links(row: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for value in extract_main_report_link_values(row):
        candidates.extend(build_report_candidates(value, source="main"))

    child_rows = row.get("__tagmon_children")
    if isinstance(child_rows, list):
        for child in child_rows:
            if isinstance(child, dict):
                utime = child.get("utime")
                for value in extract_child_report_link_values(child):
                    candidates.extend(build_report_candidates(value, source="sub", timestamp=report_timestamp_from_value(utime)))
    return candidates


def normalize_xmon_row(ioc: str, row: dict[str, Any]) -> XmonInfo:
    raw = row.get("Raw") if isinstance(row.get("Raw"), dict) else {}
    return XmonInfo(
        ioc_search=first_not_empty(row.get("ioc_search"), row.get("ioc"), row.get("IOC"), row.get("uid"), ioc),
        disable=extract_xmon_disable(row, raw),
        status=first_not_empty(row.get("status"), row.get("Status"), raw.get("status"), raw.get("Status")),
        ref_sample=row.get("ref_sample", ""),
        report_links=collect_xmon_report_links(row),
        raw=row,
    )


def empty_xmon_info(ioc: str) -> XmonInfo:
    return XmonInfo(ioc_search=ioc)


def build_xmon_batch_url(batch: list[str]) -> str:
    ioc_part = ",".join(quote(x, safe=".:_-") for x in batch)
    return f"{XMON_BASE_URL}{ioc_part}/{XMON_QUERY}"


def build_xmon_tagmon_url(iocs: list[str] | str) -> str:
    if isinstance(iocs, str):
        ioc_part = quote(iocs, safe=".:_-")
    else:
        ioc_part = ",".join(quote(x, safe=".:_-") for x in iocs)
    return f"{XMON_TAGMON_BASE_URL}{ioc_part}{XMON_TAGMON_SUFFIX}"


def chunk_xmon_iocs_by_url(iocs: list[str], url_builder, max_count: int = XMON_BATCH_SIZE) -> list[list[str]]:
    batches: list[list[str]] = []
    current: list[str] = []
    for ioc in iocs:
        candidate = current + [ioc]
        if current and (len(candidate) > max_count or len(url_builder(candidate).encode("utf-8")) > XMON_MAX_URL_BYTES):
            batches.append(current)
            current = [ioc]
            if len(url_builder(current).encode("utf-8")) > XMON_MAX_URL_BYTES:
                batches.append(current)
                current = []
        else:
            current = candidate
    if current:
        batches.append(current)
    return batches


def group_xmon_rows_by_ioc(rows: list[dict[str, Any]], prefer_search: bool = False) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if prefer_search:
            ioc = normalize_cell(first_not_empty(row.get("ioc_search"), row.get("ioc"), row.get("IOC"), row.get("uid")))
        else:
            ioc = normalize_cell(xmon_row_ioc(row))
        if not ioc:
            continue
        grouped.setdefault(ioc, []).append(row)
    return grouped


def can_resolve_host(url: str) -> tuple[bool, str]:
    host = urlparse(url).hostname or ""
    if not host:
        return False, "empty host"
    try:
        socket.getaddrinfo(host, None)
        return True, ""
    except socket.gaierror as exc:
        return False, str(exc)


def xmon_row_ioc(row: dict[str, Any]) -> str:
    return first_not_empty(row.get("ioc"), row.get("ioc_search"), row.get("IOC"), row.get("uid"))


def xmon_row_severity(row: dict[str, Any]) -> int:
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    raw = exts.get("_raw") if isinstance(exts.get("_raw"), dict) else {}
    ioctag = exts.get("ioctag") if isinstance(exts.get("ioctag"), dict) else {}
    tag_main = row.get("tag_main") if isinstance(row.get("tag_main"), dict) else {}
    return safe_int(first_not_empty(row.get("severity"), raw.get("severity"), raw.get("opinion"), ioctag.get("severity"), tag_main.get("severity")))


def is_xmon_clue_enabled(disable_text: str) -> bool:
    return not bool(normalize_cell(disable_text))


def extract_main_ioc_disabled(row: dict[str, Any]) -> str:
    return stringify(row.get("ioc_disabled", "")).strip()


def extract_child_exts_disabled(row: dict[str, Any]) -> str:
    exts = row.get("exts") if isinstance(row.get("exts"), dict) else {}
    return stringify(exts.get("disabled", "")).strip()


def build_xmon_valid_clues(main_row: dict[str, Any], child_rows: list[dict[str, Any]], requested_ioc: str = "") -> list[dict[str, Any]]:
    main_disable = extract_main_ioc_disabled(main_row)
    main_ioc = normalize_cell(requested_ioc) or normalize_cell(main_row.get("ioc", ""))
    valid_clues: list[dict[str, Any]] = []

    if is_xmon_clue_enabled(main_disable) and xmon_row_severity(main_row) > XMON_MIN_SEVERITY:
        clue = dict(main_row)
        clue["__clue_type"] = "main"
        valid_clues.append(clue)

    if not is_xmon_clue_enabled(main_disable):
        return valid_clues

    for child in child_rows:
        child_ioc = normalize_cell(child.get("ioc", ""))
        if not main_ioc or child_ioc != main_ioc:
            continue
        child_disable = extract_child_exts_disabled(child)
        if not is_xmon_clue_enabled(child_disable):
            continue
        if xmon_row_severity(child) <= XMON_MIN_SEVERITY:
            continue
        clue = dict(child)
        clue["__clue_type"] = "sub"
        valid_clues.append(clue)

    return valid_clues


def query_xmon_tagmon_batch(batch: list[str]) -> tuple[list[str], dict[str, list[dict[str, Any]]], str]:
    if not XMON_TAGMON_ENABLED or not batch:
        return batch, {ioc: [] for ioc in batch}, ""
    session = get_thread_session()
    url = build_xmon_tagmon_url(batch)
    last_error = ""
    max_attempts = XMON_TAGMON_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(XMON_TAGMON_RETRY_SLEEP)
        try:
            resp = session.get(url, headers=XMON_HEADERS, verify=False, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            grouped = group_xmon_rows_by_ioc(extract_xmon_rows(safe_json_response(resp)))
            for ioc in batch:
                grouped.setdefault(ioc, [])
            return batch, grouped, ""
        except Exception as exc:
            last_error = str(exc)
    return batch, {ioc: [] for ioc in batch}, last_error


def query_xmon_tagmon_children_many(iocs: list[str], state: PipelineState) -> dict[str, list[dict[str, Any]]]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in iocs if ioc))
    if not XMON_TAGMON_ENABLED or not unique_iocs:
        return {ioc: [] for ioc in unique_iocs}
    batches = chunk_xmon_iocs_by_url(unique_iocs, build_xmon_tagmon_url, XMON_TAGMON_BATCH_SIZE)
    if XMON_WORKERS <= 1 or len(batches) == 1:
        result_map: dict[str, list[dict[str, Any]]] = {}
        for batch in batches:
            _, grouped, error = query_xmon_tagmon_batch(batch)
            if error:
                with state.tagmon_failed_lock:
                    state.tagmon_failed_iocs.extend(f"{ioc} | {error}" for ioc in batch)
            result_map.update(grouped)
        return result_map

    result_map: dict[str, list[dict[str, Any]]] = {}
    worker_count = min(XMON_WORKERS, len(batches))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_xmon_tagmon_batch, batch): batch
            for batch in batches
        }
        for future in as_completed(future_map):
            batch = future_map[future]
            try:
                batch, grouped, error = future.result()
                result_map.update(grouped)
                if error:
                    with state.tagmon_failed_lock:
                        state.tagmon_failed_iocs.extend(f"{ioc} | {error}" for ioc in batch)
            except Exception as exc:
                with state.tagmon_failed_lock:
                    state.tagmon_failed_iocs.extend(f"{ioc} | {exc}" for ioc in batch)
                for ioc in batch:
                    result_map[ioc] = []
    return result_map


def query_xmon_main_batch(batch: list[str]) -> tuple[list[str], dict[str, list[dict[str, Any]]], str]:
    session = get_thread_session()
    url = build_xmon_batch_url(batch)
    try:
        resp = session.get(url, headers=XMON_HEADERS, verify=False, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        grouped = group_xmon_rows_by_ioc(extract_xmon_rows(safe_json_response(resp)), prefer_search=True)
        for ioc in batch:
            grouped.setdefault(ioc, [])
        return batch, grouped, ""
    except Exception as exc:
        return batch, {ioc: [] for ioc in batch}, str(exc)


def build_xmon_info_from_rows(requested_ioc: str, rows: list[dict[str, Any]], child_map: dict[str, list[dict[str, Any]]]) -> XmonInfo:
    if not rows:
        return empty_xmon_info(requested_ioc)
    row = rows[0]
    main_ioc = normalize_cell(row.get("ioc", "")) or requested_ioc
    child_rows = child_map.get(requested_ioc, child_map.get(main_ioc, []))
    enriched_row = dict(row)
    enriched_row["__tagmon_children"] = child_rows
    enriched_row["__valid_clues"] = build_xmon_valid_clues(row, child_rows, requested_ioc)
    return normalize_xmon_row(requested_ioc, enriched_row)


def query_xmon_iocs(ioc_list: list[str], state: PipelineState) -> dict[str, XmonInfo]:
    result_map: dict[str, XmonInfo] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return {}

    resolvable, resolve_error = can_resolve_host(XMON_BASE_URL)
    if not resolvable:
        host = urlparse(XMON_BASE_URL).hostname
        error = f"xmon 域名无法解析，跳过 xmon 查询：{host}，错误：{resolve_error}"
        print(f"[!] {error}")
        print("[!] 请确认当前环境能访问内网 DNS/VPN，或在 WSL/Linux 中配置可解析 xmon.netlab.qihoo.net 的 DNS/hosts。")
        state.xmon_failed_iocs.extend(f"{ioc} | {error}" for ioc in query_iocs)
        return {ioc: result_map.get(ioc, empty_xmon_info(ioc)) for ioc in ioc_list}

    main_batches = chunk_xmon_iocs_by_url(query_iocs, build_xmon_batch_url)
    max_url_bytes = max((len(build_xmon_batch_url(batch).encode("utf-8")) for batch in main_batches), default=0)
    print(
        f"[+] xmon 主线索待查询：{len(query_iocs)} 条，批量最多 {XMON_BATCH_SIZE} 条/批，"
        f"实际 {len(main_batches)} 批，最大 URL {max_url_bytes} bytes"
    )

    main_rows_map: dict[str, list[dict[str, Any]]] = {}
    worker_count = min(XMON_WORKERS, len(main_batches))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_xmon_main_batch, batch): batch for batch in main_batches}
        for future in as_completed(future_map):
            batch = future_map[future]
            try:
                batch, grouped, error = future.result()
            except Exception as exc:
                grouped = {ioc: [] for ioc in batch}
                error = str(exc)
            main_rows_map.update(grouped)
            if error:
                state.xmon_failed_iocs.extend(f"{ioc} | {error}" for ioc in batch)
            completed += len(batch)
            if completed % XMON_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] xmon 主线索查询进度：{completed}/{len(query_iocs)}")

    main_iocs = [requested_ioc for requested_ioc, rows in main_rows_map.items() if rows]
    child_batches = chunk_xmon_iocs_by_url(list(dict.fromkeys(main_iocs)), build_xmon_tagmon_url, XMON_TAGMON_BATCH_SIZE)
    child_max_url_bytes = max((len(build_xmon_tagmon_url(batch).encode("utf-8")) for batch in child_batches), default=0)
    print(
        f"[+] xmon 子线索待查询：{len(set(main_iocs))} 条，批量最多 {XMON_TAGMON_BATCH_SIZE} 条/批，"
        f"实际 {len(child_batches)} 批，最大 URL {child_max_url_bytes} bytes"
    )
    child_map = query_xmon_tagmon_children_many(main_iocs, state)

    for requested_ioc in query_iocs:
        result_map[requested_ioc] = build_xmon_info_from_rows(
            requested_ioc,
            main_rows_map.get(requested_ioc, []),
            child_map,
        )
    return {ioc: result_map.get(ioc, empty_xmon_info(ioc)) for ioc in ioc_list}
