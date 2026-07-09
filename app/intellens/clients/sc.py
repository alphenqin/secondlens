from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403


def sc_category_for_ioc(ioc: str) -> str:
    text = normalize_cell(ioc).lower()
    if text.startswith(("http://", "https://")):
        return "url"
    return SC_DEFAULT_CATEGORY


def query_custom_tags_batch(
    batch: list[str],
    category: str | None = None,
) -> tuple[list[str], dict[str, dict[str, Any]], str]:
    query_category = category or SC_DEFAULT_CATEGORY
    query_value = ",".join(batch)
    payload = {
        "query": {
            "keywords": [
                {"field": "category", "value": query_category},
                {"field": "query", "value": query_value},
                {"field": "flag", "value": "2"},
            ]
        }
    }
    try:
        resp = get_thread_session().post(
            TAGS_API_URL,
            headers=make_ti_headers(),
            data=json_utf8_body(payload),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        return batch, parse_sc_response(batch, data), ""
    except Exception as exc:
        return batch, {ioc: {"query_error": str(exc)} for ioc in batch}, str(exc)


def query_custom_tags_batch_worker(batch: list[str]) -> tuple[list[str], dict[str, dict[str, Any]], str]:
    return query_custom_tags_batch(batch)


def parse_sc_response(batch: list[str], data: Any) -> dict[str, dict[str, Any]]:
    parsed: dict[str, dict[str, Any]] = {}
    body = data.get("data") if isinstance(data, dict) else data
    if isinstance(body, dict):
        for ioc in batch:
            value = body.get(ioc, {})
            parsed[ioc] = value if isinstance(value, dict) else {"value": value}
    elif isinstance(body, list):
        for item in body:
            if not isinstance(item, dict):
                continue
            ioc = first_not_empty(item.get("ioc"), item.get("query"), item.get("domain"), item.get("ip"))
            if ioc:
                parsed[ioc] = item
    for ioc in batch:
        parsed.setdefault(ioc, {})
    return parsed


def extract_sc_level(response_json: dict[str, Any]) -> int | None:
    def find_level(value: Any) -> int | None:
        if isinstance(value, dict):
            if "level" in value:
                try:
                    return int(float(str(value.get("level")).strip()))
                except Exception:
                    return None
            for nested_key in ("data", "result", "results", "list"):
                nested_level = find_level(value.get(nested_key))
                if nested_level is not None:
                    return nested_level
        if isinstance(value, list):
            for item in value:
                nested_level = find_level(item)
                if nested_level is not None:
                    return nested_level
        return None

    return find_level(response_json)


def sc_is_malicious(response_json: dict[str, Any]) -> bool:
    level = extract_sc_level(response_json)
    return level is not None and level > 30


def query_sc(ioc_list: list[str], state: PipelineState) -> dict[str, bool]:
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    sc_map: dict[str, bool] = {}
    if not query_iocs:
        return sc_map
    batches = chunk_list(query_iocs, SC_BATCH_SIZE)
    print(
        f"[+] sc 待查询：{len(query_iocs)} 条，批量 {SC_BATCH_SIZE} 条/批，"
        f"并发数 {min(SC_WORKERS, len(batches))}"
    )

    if SC_WORKERS <= 1 or len(batches) == 1:
        completed = 0
        for batch in batches:
            _, parsed, error = query_custom_tags_batch(batch)
            if error:
                for ioc in batch:
                    state.sc_failed_iocs.append(f"{ioc} | {error}")
            for ioc in batch:
                sc_map[ioc] = sc_is_malicious(parsed.get(ioc, {}))
            completed += len(batch)
            if completed % SC_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] sc 查询进度：{completed}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
    else:
        worker_count = min(SC_WORKERS, len(batches))
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(query_custom_tags_batch_worker, batch): batch for batch in batches}
            for future in as_completed(future_map):
                fallback_batch = future_map[future]
                try:
                    batch, parsed, error = future.result()
                except Exception as exc:
                    batch = fallback_batch
                    parsed = {}
                    error = str(exc)
                if error:
                    for ioc in batch:
                        state.sc_failed_iocs.append(f"{ioc} | {error}")
                for ioc in batch:
                    sc_map[ioc] = sc_is_malicious(parsed.get(ioc, {}))
                completed += len(batch)
                if completed % SC_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                    print(f"[+] sc 查询进度：{completed}/{len(query_iocs)}")
    return sc_map

