from __future__ import annotations

import hashlib
import json
import random
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import WdInfo


def make_wd_safe_headers(body: str) -> dict[str, str]:
    nonce = str(random.randint(0, 99999999)).zfill(8)
    timestamp = str(int(time.time()))
    sign_text = hashlib.md5(body.encode("utf8")).hexdigest() + WD_SAFE_APPID + nonce + timestamp + WD_SAFE_SECRET
    signature = hashlib.md5(sign_text.encode("utf8")).hexdigest()[16:]
    return {
        "X-360-Key": WD_SAFE_APPID,
        "X-360-Nonce": nonce,
        "X-360-Timestamp": timestamp,
        "X-360-Signature": signature,
        "Content-Type": "application/json",
    }


def query_wd_safe_batch(batch: list[str]) -> tuple[list[str], dict[str, WdInfo], str]:
    body = json.dumps({"data": [{"url": ioc} for ioc in batch]}, ensure_ascii=False, separators=(",", ":"))
    try:
        session = get_thread_session()
        resp = session.post(
            WD_SAFE_API_URL,
            data=body.encode("utf-8"),
            headers=make_wd_safe_headers(body),
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        results = (((data.get("data") or {}).get("results") or []) if isinstance(data, dict) else [])
        result_map: dict[str, WdInfo] = {}
        if isinstance(results, list):
            for item in results:
                if not isinstance(item, dict):
                    continue
                ioc = normalize_cell(item.get("url", ""))
                if not ioc:
                    continue
                info = item.get("info") if isinstance(item.get("info"), dict) else {}
                level = safe_int(info.get("level"), 0)
                sub_level = safe_int(info.get("sub_level"), 0)
                result_map[ioc] = WdInfo(
                    ioc=ioc,
                    level=level,
                    sub_level=sub_level,
                    malicious=level >= 50,
                )
        for ioc in batch:
            result_map.setdefault(ioc, WdInfo(ioc=ioc, query_error="wd safe empty result"))
        return batch, result_map, ""
    except Exception as exc:
        error = str(exc)
        return batch, {ioc: WdInfo(ioc=ioc, query_error=error) for ioc in batch}, error


def wd_snapshot_row_has_content(row: dict[str, Any]) -> bool:
    title = wd_snapshot_row_title(row)
    content = wd_snapshot_row_content(row)
    return bool(content) and not wd_snapshot_is_error_page(title, content)


def wd_snapshot_valid_row_content(row: dict[str, Any]) -> str:
    title = wd_snapshot_row_title(row)
    content = wd_snapshot_row_content(row)
    if not content or wd_snapshot_is_error_page(title, content):
        return ""
    return content


def select_wd_snapshot_row(rows: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str, bool]:
    valid_rows: list[tuple[dict[str, Any], str, str]] = []
    for row in rows:
        title = wd_snapshot_row_title(row)
        content = wd_snapshot_valid_row_content(row)
        if content:
            valid_rows.append((row, title, content))
    if not valid_rows:
        return None, "", False

    titled_rows = [(row, title, content) for row, title, content in valid_rows if title]
    if titled_rows:
        max_title_len = max(len(title) for _, title, _ in titled_rows)
        longest_title_rows = [(row, title, content) for row, title, content in titled_rows if len(title) == max_title_len]
        if len(longest_title_rows) == 1:
            row, _, content = longest_title_rows[0]
            return row, content, True

    row, _, content = max(valid_rows, key=lambda item: len(item[2]))
    return row, content, False


def wd_snapshot_is_error_page(title: str, content: str) -> bool:
    text = normalize_cell(f"{title} {content}").lower()
    if not text:
        return False
    error_terms = (
        "403 forbidden",
        "404 not found",
        "400 bad request",
        "401 unauthorized",
        "500 internal server error",
        "502 bad gateway",
        "503 service temporarily unavailable",
        "504 gateway timeout",
        "access denied",
        "forbidden",
        "not found",
    )
    blocked_terms = (
        "访问失败",
        "警告",
        "抱歉，站点已暂停",
        "请求已被拦截",
    )
    if any(term in text for term in blocked_terms):
        return True
    if any(term in text for term in error_terms):
        server_terms = ("nginx", "apache", "iis", "openresty", "cloudflare")
        return any(term in text for term in server_terms) or len(text) < 300
    return False


def wd_snapshot_row_title(row: dict[str, Any]) -> str:
    return normalize_cell(row.get("title"))


def wd_snapshot_row_content(row: dict[str, Any]) -> str:
    text = normalize_cell(row.get("html"))
    if not text:
        return ""
    text = re.sub(r"(?is)<script.*?</script>", " ", text)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:4000]


def query_wd_history_snapshot(ioc: str) -> tuple[bool, str, str, str, str]:
    headers = {"X-Authtoken": WD_HISTORY_TOKEN}
    params = {"query": ioc, "time_start": WD_HISTORY_START}
    try:
        resp = get_thread_session().get(
            WD_HISTORY_API_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = safe_json_response(resp)
        rows = data.get("data") if isinstance(data, dict) else []
        if not isinstance(rows, list):
            return False, "", "", "", "wd history data is not list"
        valid_input_rows = [row for row in rows if isinstance(row, dict)]
        selected_row, content, use_title = select_wd_snapshot_row(valid_input_rows)
        if selected_row is None:
            return False, "", "", "", ""
        title = wd_snapshot_row_title(selected_row) if use_title else ""
        return True, title, title, content, ""
    except Exception as exc:
        return False, "", "", "", str(exc)


def query_wd_history_one(ioc: str) -> tuple[str, bool, str, str, str, str]:
    has_snapshot, topic, title, content, error = query_wd_history_snapshot(ioc)
    return ioc, has_snapshot, topic, title, content, error


def query_wd(ioc_list: list[str], state: PipelineState) -> dict[str, WdInfo]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    result_map: dict[str, WdInfo] = {}
    if not unique_iocs:
        return result_map

    safe_batch_size = min(WD_SAFE_BATCH_SIZE, WD_SAFE_MAX_BATCH_SIZE)
    safe_batches = chunk_list(unique_iocs, safe_batch_size)
    print(
        f"[+] wd safe 评分待查询：{len(unique_iocs)} 条，批量 {safe_batch_size} 条/批，"
        f"并发数 {min(WD_WORKERS, len(safe_batches))}"
    )
    if WD_WORKERS <= 1 or len(safe_batches) == 1:
        completed = 0
        for batch in safe_batches:
            _, parsed, error = query_wd_safe_batch(batch)
            result_map.update(parsed)
            if error:
                for ioc in batch:
                    state.wd_failed_iocs.append(f"{ioc} | {error}")
            completed += len(batch)
            if completed % WD_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
                print(f"[+] wd safe 评分查询进度：{completed}/{len(unique_iocs)}")
            time.sleep(SLEEP_SECONDS)
    else:
        worker_count = min(WD_WORKERS, len(safe_batches))
        completed = 0
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_map = {executor.submit(query_wd_safe_batch, batch): batch for batch in safe_batches}
            for future in as_completed(future_map):
                batch = future_map[future]
                try:
                    batch, parsed, error = future.result()
                except Exception as exc:
                    error = str(exc)
                    parsed = {ioc: WdInfo(ioc=ioc, query_error=error) for ioc in batch}
                result_map.update(parsed)
                if error:
                    for ioc in batch:
                        state.wd_failed_iocs.append(f"{ioc} | {error}")
                completed += len(batch)
                if completed % WD_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
                    print(f"[+] wd safe 评分查询进度：{completed}/{len(unique_iocs)}")

    malicious_iocs = [ioc for ioc, info in result_map.items() if info.malicious]
    if not malicious_iocs:
        return result_map

    print(f"[+] wd urldb 快照待查询：{len(malicious_iocs)} 条，并发数 {min(WD_WORKERS, len(malicious_iocs))}")
    if WD_WORKERS <= 1 or len(malicious_iocs) == 1:
        for index, ioc in enumerate(malicious_iocs, 1):
            _, has_snapshot, topic, title, content, snapshot_error = query_wd_history_one(ioc)
            info = result_map.get(ioc, WdInfo(ioc=ioc))
            info.has_snapshot = has_snapshot
            info.snapshot_topic = topic
            info.snapshot_title = title
            info.snapshot_content = content
            if snapshot_error:
                info.query_error = "; ".join(x for x in (info.query_error, snapshot_error) if x)
                state.wd_failed_iocs.append(f"{ioc} | {snapshot_error}")
            result_map[ioc] = info
            if index % WD_PROGRESS_INTERVAL == 0 or index == len(malicious_iocs):
                print(f"[+] wd urldb 快照查询进度：{index}/{len(malicious_iocs)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    completed = 0
    with ThreadPoolExecutor(max_workers=min(WD_WORKERS, len(malicious_iocs))) as executor:
        future_map = {executor.submit(query_wd_history_one, ioc): ioc for ioc in malicious_iocs}
        for future in as_completed(future_map):
            ioc = future_map[future]
            completed += 1
            try:
                _, has_snapshot, topic, title, content, snapshot_error = future.result()
            except Exception as exc:
                has_snapshot, topic, title, content, snapshot_error = False, "", "", "", str(exc)
            info = result_map.get(ioc, WdInfo(ioc=ioc))
            info.has_snapshot = has_snapshot
            info.snapshot_topic = topic
            info.snapshot_title = title
            info.snapshot_content = content
            if snapshot_error:
                info.query_error = "; ".join(x for x in (info.query_error, snapshot_error) if x)
                state.wd_failed_iocs.append(f"{ioc} | {snapshot_error}")
            result_map[ioc] = info
            if completed % WD_PROGRESS_INTERVAL == 0 or completed == len(malicious_iocs):
                print(f"[+] wd urldb 快照查询进度：{completed}/{len(malicious_iocs)}")
    return result_map
