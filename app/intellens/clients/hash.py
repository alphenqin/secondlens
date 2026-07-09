from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import HashInfo, XmonInfo


def first_hash_from_main_ref_sample(ref_sample: Any) -> str:
    data = parse_literal_or_json(ref_sample)
    if isinstance(data, list) and data:
        first_item = data[0]
        if isinstance(first_item, dict):
            return normalize_cell(first_item.get("md5", ""))
    return ""


def child_raw_md5(child_row: dict[str, Any]) -> str:
    exts = child_row.get("exts") if isinstance(child_row.get("exts"), dict) else {}
    raw = exts.get("_raw") if isinstance(exts.get("_raw"), dict) else {}
    return normalize_cell(raw.get("md5", ""))


def extract_hashes_from_xmon_info(xmon_info: XmonInfo) -> list[str]:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    clues = raw.get("__valid_clues")
    hashes: list[str] = []
    if isinstance(clues, list):
        for clue in clues:
            if not isinstance(clue, dict):
                continue
            clue_type = normalize_cell(clue.get("__clue_type", ""))
            if clue_type == "main":
                value = first_hash_from_main_ref_sample(clue.get("ref_sample", ""))
            elif clue_type == "sub":
                value = child_raw_md5(clue)
            else:
                value = ""
            if value:
                hashes.append(value)
    elif raw:
        # 兼容旧运行结果或异常返回结构：有效线索列表缺失时，仍按主线索规则兜底提取一次。
        from app.intellens.clients.xmon import extract_main_ioc_disabled, is_xmon_clue_enabled, xmon_row_severity

        main_disable = extract_main_ioc_disabled(raw)
        if is_xmon_clue_enabled(main_disable) and xmon_row_severity(raw) > XMON_MIN_SEVERITY:
            value = first_hash_from_main_ref_sample(raw.get("ref_sample", ""))
            if value:
                hashes.append(value)
    return list(dict.fromkeys(hashes))


def query_hash_batch(hash_list: list[str], state: PipelineState) -> Any:
    payload = {"param": ",".join(hash_list), "field": 0}
    try:
        resp = get_thread_session().post(
            HASH_API_URL,
            headers=make_ti_headers(),
            data=json_utf8_body(payload),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return safe_json_response(resp)
    except Exception as exc:
        with state.hash_failed_lock:
            state.hash_failed_queries.append(f"{','.join(hash_list)} | {exc}")
        return {"errno": -1, "msg": str(exc), "result": {}}


def query_hash_batch_worker(hash_batch: list[str], state: PipelineState) -> tuple[list[str], dict[str, HashInfo]]:
    response_json = query_hash_batch(hash_batch, state)
    parsed = parse_hash_result(hash_batch, response_json)
    return hash_batch, parsed


def parse_hash_result(hash_list: list[str], response_json: Any) -> dict[str, HashInfo]:
    if not isinstance(response_json, dict):
        response_json = {}
    result = response_json.get("result", {}) or response_json.get("data", {}) or {}
    hash_map: dict[str, HashInfo] = {}
    result_by_lower_key: dict[str, dict[str, Any]] = {}
    result_by_embedded_hash: dict[str, dict[str, Any]] = {}
    if isinstance(result, dict):
        for key, value in result.items():
            if not isinstance(value, dict):
                continue
            key_text = normalize_cell(key).lower()
            if key_text:
                result_by_lower_key[key_text] = value
            for hash_key in ("md5", "sha1", "sha256"):
                embedded = normalize_cell(value.get(hash_key, "")).lower()
                if embedded:
                    result_by_embedded_hash[embedded] = value

    for h in hash_list:
        hash_key = normalize_cell(h).lower()
        item = {}
        if isinstance(result, dict):
            direct_item = result.get(h, {})
            if isinstance(direct_item, dict):
                item = direct_item
        if not item:
            item = result_by_lower_key.get(hash_key, {})
        if not item:
            item = result_by_embedded_hash.get(hash_key, {})
        if not isinstance(item, dict):
            item = {}
        threat_type = item.get("threat_type", {}) if isinstance(item.get("threat_type"), dict) else {}
        hash_map[h] = HashInfo(
            query_hash=h,
            risk=normalize_cell(item.get("risk", "")),
            file_size=normalize_cell(item.get("file_size", "")),
            file_type=normalize_cell(item.get("file_type", "")),
            first_seen_time=timestamp_to_date(first_not_empty(item.get("first_seen"), item.get("create_time"), item.get("createtime"))),
            operating_system=normalize_cell(item.get("operating_system", "")),
            malware_family=normalize_cell(item.get("malware_family", "")),
            virus_name=normalize_cell(item.get("virus_name", "")),
            threat_type_name=normalize_cell(threat_type.get("name", "")),
        )
    return hash_map


def query_hashes(hash_list: list[str], state: PipelineState) -> dict[str, HashInfo]:
    unique_hashes = list(dict.fromkeys(h for h in hash_list if h))
    all_hash_map: dict[str, HashInfo] = {}
    if not unique_hashes:
        return all_hash_map
    batch_size = min(HASH_BATCH_SIZE, HASH_MAX_BATCH_SIZE)
    batches = chunk_list(unique_hashes, batch_size)
    print(
        f"[+] 查询 hash：{len(unique_hashes)} 条，批量 {batch_size} 条/批，"
        f"并发数 {min(HASH_WORKERS, len(batches))}"
    )
    if HASH_WORKERS <= 1 or len(batches) == 1:
        completed = 0
        for hash_batch in batches:
            response_json = query_hash_batch(hash_batch, state)
            parsed = parse_hash_result(hash_batch, response_json)
            all_hash_map.update(parsed)
            completed += len(hash_batch)
            if completed % HASH_PROGRESS_INTERVAL == 0 or completed == len(unique_hashes):
                print(f"[+] hash 查询进度：{completed}/{len(unique_hashes)}")
            time.sleep(SLEEP_SECONDS)
        return all_hash_map

    worker_count = min(HASH_WORKERS, len(batches))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(query_hash_batch_worker, hash_batch, state): hash_batch for hash_batch in batches}
        for future in as_completed(future_map):
            hash_batch = future_map[future]
            try:
                hash_batch, parsed = future.result()
                all_hash_map.update(parsed)
            except Exception as exc:
                with state.hash_failed_lock:
                    state.hash_failed_queries.append(f"{','.join(hash_batch)} | {exc}")
                for hash_value in hash_batch:
                    all_hash_map[hash_value] = HashInfo(query_hash=hash_value)
            completed += len(hash_batch)
            if completed % HASH_PROGRESS_INTERVAL == 0 or completed == len(unique_hashes):
                print(f"[+] hash 查询进度：{completed}/{len(unique_hashes)}")
    return all_hash_map
