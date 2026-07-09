from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "docs" / "webapi2" / "py3" / "apps" / "intellens" / "config"
APP_ENV = os.getenv("INTELLENS_ENV") or os.getenv("APP_ENV") or "dev"
APP_CONFIG_FILE = Path(os.getenv("INTELLENS_CONFIG", DEFAULT_CONFIG_DIR / f"{APP_ENV}.yaml"))


def _load_app_config() -> dict[str, Any]:
    if not APP_CONFIG_FILE.exists():
        return {}
    with APP_CONFIG_FILE.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise RuntimeError(f"IntelLens config file must contain a mapping: {APP_CONFIG_FILE}")
    return data


def _as_bool(value: Any, default: bool = False) -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: Any, default: int) -> int:
    if value in (None, ""):
        return default
    return int(value)


def _as_float(value: Any, default: float) -> float:
    if value in (None, ""):
        return default
    return float(value)


def _section(name: str) -> dict[str, Any]:
    section = APP_CONFIG.get(name, {})
    if not isinstance(section, dict):
        raise RuntimeError(f"IntelLens config section must be object: {name}")
    return section


def _nested_section(parent: dict[str, Any], name: str) -> dict[str, Any]:
    section = parent.get(name, {})
    if not isinstance(section, dict):
        raise RuntimeError(f"IntelLens config section must be object: {name}")
    return section


def _str(section: dict[str, Any], key: str, default: str = "") -> str:
    return str(section.get(key) or default)


APP_CONFIG = _load_app_config()
EXTERNAL_SERVICES_CONFIG = _section("external_services")
PERFORMANCE_CONFIG = _section("performance")

VENDOR = "360"

XMON_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "xmon")
XMON_BASE_URL = _str(XMON_CONFIG, "base_url")
XMON_QUERY = _str(XMON_CONFIG, "query")
XMON_TAGMON_BASE_URL = _str(XMON_CONFIG, "tagmon_base_url")
XMON_TAGMON_SUFFIX = _str(XMON_CONFIG, "tagmon_suffix")
XMON_TOKEN = _str(XMON_CONFIG, "token")
XMON_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-AuthToken": XMON_TOKEN,
    "Pragma": "no-cache",
    "Referer": "http://xmon.netlab.qihoo.net/ui/iocmon/",
    "User-Agent": "Mozilla/5.0",
    "X-Requested-With": "XMLHttpRequest",
}
if XMON_CONFIG.get("cookie"):
    XMON_HEADERS["Cookie"] = str(XMON_CONFIG["cookie"])

HASH_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "hash")
HASH_API_URL = _str(HASH_CONFIG, "api_url")
API_KEY = _str(HASH_CONFIG, "api_key")
SALT = _str(HASH_CONFIG, "salt")

WFY_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "wfy")
WFY_API_URL = _str(WFY_CONFIG, "api_url")
WFY_HEADERS = {"Content-Type": "application/json", "X-AuthToken": XMON_TOKEN}

WD_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "wd")
WD_SAFE_API_URL = _str(WD_CONFIG, "safe_api_url")
WD_SAFE_APPID = _str(WD_CONFIG, "safe_appid")
WD_SAFE_SECRET = _str(WD_CONFIG, "safe_secret")
WD_HISTORY_API_URL = _str(WD_CONFIG, "history_api_url")
WD_HISTORY_TOKEN = _str(WD_CONFIG, "history_token")
WD_HISTORY_START = _str(WD_CONFIG, "history_start")

SC_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "sc")
TAGS_API_URL = _str(SC_CONFIG, "tags_api_url")
SC_DEFAULT_CATEGORY = _str(SC_CONFIG, "default_category", "domain")

AI_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "ai")
AI_QUICK_ANALYSIS_URL = _str(AI_CONFIG, "quick_analysis_url")
AI_QUICK_ANALYSIS_HEADERS = {"Content-Type": "application/json", "X-AuthToken": XMON_TOKEN}
AI_KEY_EVIDENCE_DROP_TERMS = ("外部威胁情报", "威胁情报状态", "外部")
AI_EVIDENCE_PROMPT = (
    "将以下内容汇总为一句情报研判依据，长度50字左右。"
    "若信息不足以形成依据，请返回空字符串。不要输出安全声明、伦理声明、拒答说明或无关建议。"
)

EXTERNAL_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "external")
EXTERNAL_WB_IOC_SEARCH_URL = _str(EXTERNAL_CONFIG, "wb_ioc_search_url")
EXTERNAL_QAX_IOC_SEARCH_URL = _str(EXTERNAL_CONFIG, "qax_ioc_search_url")
EXTERNAL_IOC_HEADERS = {"Content-Type": "application/json", "X-AuthToken": XMON_TOKEN}
EXTERNAL_QAX_HEADERS = {"X-AuthToken": XMON_TOKEN}
EXTERNAL_WB_HIT_RULE = "外部wb接口证据链"
EXTERNAL_QAX_HIT_RULE = "外部qax接口证据链"
EXTERNAL_QAX_HAZARD_LEVELS = {"low", "medium", "high", "critical"}

LLM_CONFIG = _nested_section(EXTERNAL_SERVICES_CONFIG, "llm")
LLM_API_URL = _str(LLM_CONFIG, "api_url")
LLM_MODEL = _str(LLM_CONFIG, "model")
LLM_TOKEN = _str(LLM_CONFIG, "token")
LLM_SUMMARY_MAX_TOKENS = _as_int(LLM_CONFIG.get("summary_max_tokens"), 800)

SIYUBO_NO_RESULT = "信息有限，无对应研判结果"
SIYUBO_NO_RESULT_TERMS = ("无法研判", "无法判断", "不能研判", "信息有限", "无对应研判结果")
SIYUBO_HIT_TERMS = ("恶意", "可疑", "怀疑", "风险")
SIYUBO_EVIDENCE_PROMPT = (
    "请先判断evidence_chain中的detail是否能支持该IOC为恶意、风险或可疑IOC。"
    f"如果完全没有恶意/风险/可疑依据，只输出：{SIYUBO_NO_RESULT}。"
    "不要输出判断过程、编号、前缀或解释。"
)
ATATEAM_NO_RESULT = "证据链不合格，无法生成恶意依据。"
ATATEAM_NO_RESULT_TERMS = ("证据链不合格", "无法生成恶意依据", "无法研判", "无法判断", "不能研判", "信息有限", "无对应研判结果")
ATATEAM_EVIDENCE_PROMPT = (
    "你是一名威胁情报分析专家，请根据输入的结构化证据链生成一句情报依据。"
    "输入字段可能包含sample_behavior、source_links、related_vulnerabilities、traffic_fragments、other_evidence。"
    f"若所有字段均为空，或没有恶意/风险/可疑依据，只输出：{ATATEAM_NO_RESULT}"
)
AI_NO_RESULT_TERMS = ("无法研判", "无法判断", "不能研判", "信息有限", "无对应研判结果", "信息不足", "空字符串")
AI_REFUSAL_TERMS = ("无法回答", "不能回答", "有益知识", "法律与道德", "有建设性的话题", "遵守所有相关")

REQUEST_TIMEOUT = _as_int(PERFORMANCE_CONFIG.get("request_timeout"), 20)
HTTP_POOL_CONNECTIONS = _as_int(PERFORMANCE_CONFIG.get("http_pool_connections"), 20)
HTTP_POOL_MAXSIZE = _as_int(PERFORMANCE_CONFIG.get("http_pool_maxsize"), 50)
XMON_WORKERS = _as_int(PERFORMANCE_CONFIG.get("xmon_workers"), 4)
XMON_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("xmon_batch_size"), 20)
XMON_TAGMON_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("xmon_tagmon_batch_size"), 20)
XMON_MAX_URL_BYTES = _as_int(PERFORMANCE_CONFIG.get("xmon_max_url_bytes"), 7000)
XMON_PROGRESS_INTERVAL = _as_int(PERFORMANCE_CONFIG.get("xmon_progress_interval"), 100)
XMON_TAGMON_ENABLED = _as_bool(PERFORMANCE_CONFIG.get("xmon_tagmon_enabled"), True)
XMON_TAGMON_RETRIES = _as_int(PERFORMANCE_CONFIG.get("xmon_tagmon_retries"), 2)
XMON_TAGMON_RETRY_SLEEP = _as_float(PERFORMANCE_CONFIG.get("xmon_tagmon_retry_sleep"), 0.2)
HASH_WORKERS = _as_int(PERFORMANCE_CONFIG.get("hash_workers"), 4)
HASH_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("hash_batch_size"), 20)
HASH_MAX_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("hash_max_batch_size"), 50)
HASH_PROGRESS_INTERVAL = _as_int(PERFORMANCE_CONFIG.get("hash_progress_interval"), 100)
WFY_WORKERS = _as_int(PERFORMANCE_CONFIG.get("wfy_workers"), 4)
WFY_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("wfy_batch_size"), 20)
WFY_MAX_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("wfy_max_batch_size"), 50)
WFY_PROGRESS_INTERVAL = _as_int(PERFORMANCE_CONFIG.get("wfy_progress_interval"), 100)
WFY_RETRIES = _as_int(PERFORMANCE_CONFIG.get("wfy_retries"), 2)
WFY_RETRY_SLEEP_SECONDS = _as_float(PERFORMANCE_CONFIG.get("wfy_retry_sleep_seconds"), 0.2)
EXTERNAL_WB_WORKERS = _as_int(PERFORMANCE_CONFIG.get("external_wb_workers"), 4)
EXTERNAL_WB_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("external_wb_batch_size"), 20)
EXTERNAL_WB_MAX_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("external_wb_max_batch_size"), 50)
EXTERNAL_QAX_WORKERS = _as_int(PERFORMANCE_CONFIG.get("external_qax_workers"), 4)
EXTERNAL_PROGRESS_INTERVAL = _as_int(PERFORMANCE_CONFIG.get("external_progress_interval"), 100)
SC_WORKERS = _as_int(PERFORMANCE_CONFIG.get("sc_workers"), 4)
SC_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("sc_batch_size"), 20)
SC_PROGRESS_INTERVAL = _as_int(PERFORMANCE_CONFIG.get("sc_progress_interval"), 100)
WD_WORKERS = _as_int(PERFORMANCE_CONFIG.get("wd_workers"), 4)
WD_SAFE_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("wd_safe_batch_size"), 20)
WD_SAFE_MAX_BATCH_SIZE = _as_int(PERFORMANCE_CONFIG.get("wd_safe_max_batch_size"), 50)
WD_HISTORY_WORKERS = _as_int(PERFORMANCE_CONFIG.get("wd_history_workers"), 4)
WD_PROGRESS_INTERVAL = _as_int(PERFORMANCE_CONFIG.get("wd_progress_interval"), 100)
AI_WORKERS = _as_int(PERFORMANCE_CONFIG.get("ai_workers"), 4)
LLM_WORKERS = _as_int(PERFORMANCE_CONFIG.get("llm_workers"), 4)
AI_PROGRESS_INTERVAL = _as_int(PERFORMANCE_CONFIG.get("ai_progress_interval"), 100)
SLEEP_SECONDS = _as_float(PERFORMANCE_CONFIG.get("sleep_seconds"), 0.0)
DEBUG_IOCS = set()
BLACK_RISKS = {"black", "malicious", "high", "danger", "risk"}
WHITE_RISKS = {"white", "clean", "safe"}
OWNER_PRIORITY = ("atateam", "siyubo", "wd", "netlab", "unknown")
