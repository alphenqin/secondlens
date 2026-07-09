from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import ExternalIocInfo


def external_wb_item_is_malicious(item: dict[str, Any]) -> bool:
    data = item.get("data")
    if not isinstance(data, dict):
        return False
    contexts = data.get("contexts")
    if not isinstance(contexts, list):
        return False
    for context in contexts:
        if not isinstance(context, dict):
            continue
        severity = normalize_cell(context.get("severity"))
        if severity and severity != "0":
            return True
    return False


def parse_external_wb_response(batch: list[str], data: Any) -> dict[str, ExternalIocInfo]:
    parsed = {ioc: ExternalIocInfo(ioc=ioc) for ioc in batch}
    results = data.get("results") if isinstance(data, dict) else []
    if not isinstance(results, list):
        return parsed
    for item in results:
        if not isinstance(item, dict):
            continue
        ioc = normalize_cell(item.get("ioc"))
        if not ioc:
            continue
        info = parsed.setdefault(ioc, ExternalIocInfo(ioc=ioc))
        if external_wb_item_is_malicious(item):
            info.hit_rule = EXTERNAL_WB_HIT_RULE
    return parsed


def query_external_wb_batch(batch: list[str]) -> tuple[list[str], dict[str, ExternalIocInfo], str]:
    try:
        session = get_thread_session()
        payload = {"iocs": batch}
        resp = session.post(
            EXTERNAL_WB_IOC_SEARCH_URL,
            headers=EXTERNAL_IOC_HEADERS,
            data=json_utf8_body(payload),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        return batch, parse_external_wb_response(batch, data), ""
    except Exception as exc:
        error = str(exc)
        return batch, {ioc: ExternalIocInfo(ioc=ioc, query_error=error) for ioc in batch}, error


def query_external_wb_iocs(ioc_list: list[str], state: PipelineState) -> dict[str, ExternalIocInfo]:
    result_map: dict[str, ExternalIocInfo] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return result_map
    batch_size = min(EXTERNAL_WB_BATCH_SIZE, EXTERNAL_WB_MAX_BATCH_SIZE)
    batches = chunk_list(query_iocs, batch_size)
    print(
        f"[+] 外部 wb 接口待查询：{len(query_iocs)} 条，批量 {batch_size} 条/批，"
        f"并发数 {min(EXTERNAL_WB_WORKERS, len(batches))}"
    )
    completed = 0
    if EXTERNAL_WB_WORKERS <= 1 or len(batches) == 1:
        for batch in batches:
            _, parsed, error = query_external_wb_batch(batch)
            result_map.update(parsed)
            if error:
                state.external_ioc_failed_queries.extend(f"{ioc} | wb接口查询失败：{error}" for ioc in batch)
            completed += len(batch)
            if completed % EXTERNAL_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] 外部 wb 接口查询进度：{completed}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(EXTERNAL_WB_WORKERS, len(batches))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_external_wb_batch, batch): batch for batch in batches}
        for future in as_completed(future_map):
            fallback_batch = future_map[future]
            try:
                batch, parsed, error = future.result()
            except Exception as exc:
                batch = fallback_batch
                error = str(exc)
                parsed = {ioc: ExternalIocInfo(ioc=ioc, query_error=error) for ioc in batch}
            result_map.update(parsed)
            if error:
                state.external_ioc_failed_queries.extend(f"{ioc} | wb接口查询失败：{error}" for ioc in batch)
            completed += len(batch)
            if completed % EXTERNAL_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] 外部 wb 接口查询进度：{completed}/{len(query_iocs)}")
    return result_map


def parse_external_qax_response(ioc: str, data: Any) -> ExternalIocInfo:
    info = ExternalIocInfo(ioc=ioc)
    rows = data.get("data") if isinstance(data, dict) else []
    if not isinstance(rows, list):
        return info
    for row in rows:
        if not isinstance(row, dict):
            continue
        hazard_level = normalize_cell(row.get("hazard_level")).lower()
        if hazard_level in EXTERNAL_QAX_HAZARD_LEVELS:
            info.hit_rule = EXTERNAL_QAX_HIT_RULE
            return info
    return info


def query_external_qax_one(ioc: str) -> ExternalIocInfo:
    try:
        session = get_thread_session()
        resp = session.get(
            EXTERNAL_QAX_IOC_SEARCH_URL,
            headers=EXTERNAL_QAX_HEADERS,
            params={"ioc": ioc},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        return parse_external_qax_response(ioc, data)
    except Exception as exc:
        return ExternalIocInfo(ioc=ioc, query_error=str(exc))


def query_external_qax_iocs(ioc_list: list[str], state: PipelineState) -> dict[str, ExternalIocInfo]:
    result_map: dict[str, ExternalIocInfo] = {}
    query_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    if not query_iocs:
        return result_map
    worker_count = min(max(EXTERNAL_QAX_WORKERS, 1), len(query_iocs))
    print(f"[+] 外部 qax 接口待查询：{len(query_iocs)} 条，并发数 {worker_count}")
    completed = 0
    if worker_count <= 1:
        for ioc in query_iocs:
            info = query_external_qax_one(ioc)
            result_map[ioc] = info
            if info.query_error:
                state.external_ioc_failed_queries.append(f"{ioc} | qax接口查询失败：{info.query_error}")
            completed += 1
            if completed % EXTERNAL_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] 外部 qax 接口查询进度：{completed}/{len(query_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_external_qax_one, ioc): ioc for ioc in query_iocs}
        for future in as_completed(future_map):
            ioc = future_map[future]
            try:
                info = future.result()
            except Exception as exc:
                info = ExternalIocInfo(ioc=ioc, query_error=str(exc))
            result_map[ioc] = info
            if info.query_error:
                state.external_ioc_failed_queries.append(f"{ioc} | qax接口查询失败：{info.query_error}")
            completed += 1
            if completed % EXTERNAL_PROGRESS_INTERVAL == 0 or completed == len(query_iocs):
                print(f"[+] 外部 qax 接口查询进度：{completed}/{len(query_iocs)}")
    return result_map


def query_external_ioc_evidence(ioc_list: list[str], state: PipelineState) -> dict[str, ExternalIocInfo]:
    result_map = query_external_wb_iocs(ioc_list, state)
    qax_iocs = [
        ioc
        for ioc in ioc_list
        if ioc and not result_map.get(ioc, ExternalIocInfo(ioc=ioc)).malicious
    ]
    qax_map = query_external_qax_iocs(qax_iocs, state)
    result_map.update(qax_map)
    wb_count = sum(1 for info in result_map.values() if info.hit_rule == EXTERNAL_WB_HIT_RULE)
    qax_count = sum(1 for info in result_map.values() if info.hit_rule == EXTERNAL_QAX_HIT_RULE)
    print(f"[+] 外部接口证据链命中：wb {wb_count} 条，qax {qax_count} 条")
    return result_map

