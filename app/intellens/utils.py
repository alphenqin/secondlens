"""IntelLens 通用工具：单元格规整、JSON/请求体、Session 与连接池、时间/大小格式化、表头构造等。
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import time
from typing import Any

import requests
from requests import Session
from requests.adapters import HTTPAdapter

from app.intellens import config
from app.intellens import state


def first_not_empty(*values: Any) -> str:
    for value in values:
        text = stringify(value).strip()
        if text:
            return text
    return ""


def stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value != value:
        return ""
    if isinstance(value, list):
        return " ".join(stringify(v) for v in value if stringify(v))
    if isinstance(value, dict):
        if "in" in value and "out" in value:
            return f"{stringify(value.get('in'))} {stringify(value.get('out'))}".strip()
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def json_utf8_body(value: Any, **kwargs: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, **kwargs).encode("utf-8")


def normalize_cell(value: Any) -> str:
    text = stringify(value).strip()
    if text in {"--", "nan", "NaN", "None"}:
        return ""
    if re.fullmatch(r"\d+\.0", text):
        return text[:-2]
    return text


def normalize_epoch_seconds(value: int) -> int:
    if value > 10_000_000_000:
        return value // 1000
    return value


def make_session() -> Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=config.HTTP_POOL_CONNECTIONS,
        pool_maxsize=config.HTTP_POOL_MAXSIZE,
        pool_block=False,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_thread_session() -> Session:
    session = getattr(state.THREAD_LOCAL, "session", None)
    if session is None:
        session = make_session()
        state.THREAD_LOCAL.session = session
    return session


def chunk_list(data: list[str], size: int) -> list[list[str]]:
    if size <= 0:
        size = 1
    return [data[i : i + size] for i in range(0, len(data), size)]


def timestamp_to_date(ts: Any) -> str:
    try:
        value = int(float(str(ts).strip()))
        if value <= 0:
            return ""
        value = normalize_epoch_seconds(value)
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))
    except Exception:
        return normalize_cell(ts)


def format_file_size(byte_value: Any) -> str:
    text = normalize_cell(byte_value)
    if not text:
        return ""
    try:
        size = int(float(text))
    except Exception:
        return text

    units = ["bytes", "KB", "MB", "GB", "TB"]
    value = float(size)
    unit_index = 0
    while value >= 1024 and unit_index < len(units) - 1:
        value /= 1024
        unit_index += 1

    if unit_index == 0:
        return f"{size} bytes ({size} bytes)"
    return f"{value:.2f} {units[unit_index]} ({size} bytes)"


def build_ioc(row: dict[str, Any]) -> str:
    target = normalize_cell(row.get("外联目标", ""))
    port = normalize_cell(row.get("端口", ""))
    target_type = normalize_cell(row.get("目标类型", "")).upper()
    if not target:
        return ""
    if target_type == "IP" and port:
        return f"{target}:{port}"
    return target


def excel_row_is_abnormal(row: dict[str, Any]) -> bool:
    target = normalize_cell(row.get("外联目标", ""))
    port = normalize_cell(row.get("端口", ""))
    target_type = normalize_cell(row.get("目标类型", "")).upper()
    return bool(target and target_type == "IP" and not port)


def result_ioc(row: dict[str, Any]) -> str:
    return normalize_cell(row.get("外联目标", "")) or normalize_cell(row.get("ioc", ""))


def make_ti_headers() -> dict[str, str]:
    timestamp = int(time.time())
    sign = hashlib.md5((str(timestamp) + config.SALT).encode()).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Api-Key": config.API_KEY,
        "timestamp": str(timestamp),
        "sign": sign,
    }


def safe_json_response(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return {}


def parse_literal_or_json(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return value
    text = stringify(value).strip()
    if not text:
        return []
    for parser in (json.loads, ast.literal_eval):
        try:
            return parser(text)
        except Exception:
            pass
    return text


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default
