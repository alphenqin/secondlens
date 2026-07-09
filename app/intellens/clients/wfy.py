"""IntelLens wfy 声誉查询客户端。
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403


def query_wfy_batch(batch: list[str]) -> tuple[list[str], dict[str, dict[str, Any]], str]:
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
            return batch, parse_wfy_response(batch, data), ""
        except Exception as exc:
            last_error = str(exc)
            if attempt < max_attempts:
                time.sleep(WFY_RETRY_SLEEP_SECONDS * (2 ** (attempt - 1)))
                continue
            return batch, {ioc: {"query_error": last_error, "judge": ""} for ioc in batch}, last_error
    last_error = last_error or "wfy query failed"
    return batch, {ioc: {"query_error": last_error, "judge": ""} for ioc in batch}, last_error


def query_wfy(ioc_list: list[str], state: PipelineState) -> dict[str, dict[str, Any]]:
    result_map: dict[str, dict[str, Any]] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return result_map
    batch_size = min(WFY_BATCH_SIZE, WFY_MAX_BATCH_SIZE)
    batches = chunk_list(query_iocs, batch_size)
    print(
        f"[+] wfy 待查询：{len(query_iocs)} 条，批量 {batch_size} 条/批，"
        f"并发数 {min(WFY_WORKERS, len(batches))}，429/异常最多重试 {WFY_RETRIES} 次"
    )

    if WFY_WORKERS <= 1 or len(batches) == 1:
        completed = 0
        for batch in batches:
            _, parsed, error = query_wfy_batch(batch)
            result_map.update(parsed)
            if error:
                for ioc in batch:
                    state.wfy_failed_queries.append(f"{ioc} | {error}")
            completed += len(batch)
            if completed % WFY_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] wfy 查询进度：{completed}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(WFY_WORKERS, len(batches))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_wfy_batch, batch): batch for batch in batches}
        for future in as_completed(future_map):
            fallback_batch = future_map[future]
            try:
                batch, parsed, error = future.result()
            except Exception as exc:
                batch = fallback_batch
                error = str(exc)
                parsed = {ioc: {"query_error": error, "judge": ""} for ioc in batch}
            result_map.update(parsed)
            if error:
                for ioc in batch:
                    state.wfy_failed_queries.append(f"{ioc} | {error}")
            completed += len(batch)
            if completed % WFY_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] wfy 查询进度：{completed}/{len(query_iocs)}")
    return result_map


def normalize_wfy_value(query_ioc: str, value: Any) -> dict[str, Any]:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict) and normalize_cell(item.get("ioc")) == query_ioc:
                return item
    return {}


def parse_wfy_response(batch: list[str], data: Any) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    if isinstance(data, dict):
        candidate = data.get("data")
        if isinstance(candidate, dict):
            for ioc in batch:
                value = candidate.get(ioc, candidate.get("query_ioc", []))
                parsed[ioc] = normalize_wfy_value(ioc, value)
            return parsed

    for ioc in batch:
        parsed.setdefault(ioc, {})
    return parsed
