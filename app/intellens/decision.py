"""IntelLens 研判规则：owner 归属、报告链接选取、wd 快照规则、decide_row 主决策、decision→row 转换。
"""
from __future__ import annotations

import re
import ipaddress
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import AiInfo, ExternalIocInfo, HashInfo, RowDecision, WdInfo, XmonInfo
from app.intellens.clients.hash import extract_hashes_from_xmon_info
from app.intellens.clients.llm import query_wd_snapshot_llm_topic


def wfy_judge(wfy_info: dict[str, Any]) -> str:
    return normalize_cell(wfy_info.get("judge")).lower()


def wfy_is_black(wfy_info: dict[str, Any]) -> bool:
    return wfy_judge(wfy_info) == "black"


def wfy_is_white(wfy_info: dict[str, Any]) -> bool:
    return wfy_judge(wfy_info) in {"white", "whitelist", "safe"}


def wfy_is_unknown(wfy_info: dict[str, Any]) -> bool:
    judge = wfy_judge(wfy_info)
    return not judge or judge == "unknown"


def risk_is_black(risk: str) -> bool:
    return normalize_cell(risk).lower() in BLACK_RISKS


def risk_is_white(risk: str) -> bool:
    return normalize_cell(risk).lower() in WHITE_RISKS


def map_wfy_status(wfy_status: Any) -> str:
    status = normalize_cell(wfy_status).upper()
    status_map = {
        "ACTIVE": "存活",
        "UNKNOWN": "存活",
        "OVER": "失活",
        "SINKHOLE": "被安全机构接管",
        "": "存活",
    }
    return status_map.get(status, status)


REPORT_DEFAULT_TIMESTAMP = 0
REPORT_URL_RE = re.compile(r"https?://[^\s\"'<>，；、（）()\\\\]+")
REPORT_URL_BLACKLIST_DOMAINS = {"dbl.oisd.nl"}
REPORT_DATETIME_PATTERNS = (
    re.compile(r"(?P<date>\d{4}[-/]\d{1,2}[-/]\d{1,2})(?:[T_\s]+(?P<time>\d{1,2}[:：]\d{1,2}(?:[:：]\d{1,2})?))?"),
    re.compile(r"(?P<date>\d{8})[_-]?(?P<time>\d{6})"),
)
REPORT_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)


def clean_report_url(url: str) -> str:
    text = normalize_cell(url).strip().strip("\"'").rstrip(".,;，；。")
    if not text:
        return ""
    for marker in ("@Version:", "@version:", "@VERSION:", "@"):
        if marker in text:
            text = text.split(marker, 1)[0]
            break
    if "#" in text:
        text = text.split("#", 1)[0]
    return text.rstrip(".,;，；。")


def is_valid_report_url(url: str) -> bool:
    if not url or re.search(r"\s|\\", url):
        return False
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    if parsed.username or parsed.password:
        return False
    try:
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False
    except ValueError:
        return False

    host = (parsed.hostname or "").strip().rstrip(".")
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(REPORT_HOST_RE.fullmatch(host))


def report_timestamp_from_value(value: Any) -> int:
    text = normalize_cell(value)
    if not text:
        return REPORT_DEFAULT_TIMESTAMP

    numeric = text.strip()
    if re.fullmatch(r"\d+(?:\.\d+)?", numeric):
        try:
            timestamp = int(float(numeric))
            timestamp = normalize_epoch_seconds(timestamp)
            return timestamp if timestamp > 0 else REPORT_DEFAULT_TIMESTAMP
        except Exception:
            pass

    best_timestamp = REPORT_DEFAULT_TIMESTAMP
    for pattern in REPORT_DATETIME_PATTERNS:
        for match in pattern.finditer(text):
            date_part = match.group("date")
            time_part = match.groupdict().get("time") or "00:00:00"
            try:
                if len(date_part) == 8:
                    normalized = f"{date_part[:4]}-{date_part[4:6]}-{date_part[6:8]} {time_part[:2]}:{time_part[2:4]}:{time_part[4:6]}"
                else:
                    if time_part.count(":") == 1 or time_part.count("：") == 1:
                        time_part = f"{time_part}:00"
                    normalized = f"{date_part.replace('/', '-')} {time_part.replace('：', ':')}"
                dt = datetime.strptime(normalized, "%Y-%m-%d %H:%M:%S")
                best_timestamp = max(best_timestamp, int(dt.replace(tzinfo=timezone.utc).timestamp()))
            except Exception:
                continue
    return best_timestamp


def iter_report_text_values(value: Any) -> list[Any]:
    data = parse_literal_or_json(value)
    if isinstance(data, dict):
        values: list[Any] = list(data.keys()) + list(data.values())
    elif isinstance(data, list):
        values = data
    else:
        values = [data]
    return values


def build_report_candidates(value: Any, source: str = "", timestamp: int | None = None) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in iter_report_text_values(value):
        if isinstance(item, (dict, list)):
            candidates.extend(build_report_candidates(item, source=source, timestamp=timestamp))
            continue
        text = stringify(item)
        item_timestamp = report_timestamp_from_value(text) if timestamp is None else timestamp
        for match in REPORT_URL_RE.findall(text):
            url = clean_report_url(match)
            if is_valid_report_url(url):
                candidates.append({"url": url, "timestamp": item_timestamp, "source": source})
    return candidates


def normalize_report_url(url: str) -> str:
    return clean_report_url(url)


def is_blacklisted_report_url(url: str) -> bool:
    parsed = urlparse(normalize_report_url(url))
    host = (parsed.hostname or "").strip().rstrip(".").lower()
    return host in REPORT_URL_BLACKLIST_DOMAINS


def pick_first_report(report_links: Any) -> str:
    if isinstance(report_links, list) and all(isinstance(item, dict) and "url" in item for item in report_links):
        candidates = report_links
    else:
        candidates = build_report_candidates(report_links)

    best_url = ""
    best_timestamp = -1
    for candidate in candidates:
        url = normalize_report_url(candidate.get("url", ""))
        if not is_valid_report_url(url):
            continue
        if is_blacklisted_report_url(url):
            continue
        timestamp = safe_int(candidate.get("timestamp"), REPORT_DEFAULT_TIMESTAMP)
        if timestamp > best_timestamp:
            best_url = url
            best_timestamp = timestamp
    return best_url


def all_xmon_text(xmon_info: XmonInfo) -> str:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    if "__valid_clues" in raw:
        return stringify(raw.get("__valid_clues") or []).lower()

    fields = [
        xmon_info.ioc_search,
        xmon_info.disable,
        xmon_info.status,
        xmon_info.report_links,
        raw.get("src"),
        raw.get("source"),
        raw.get("src_end"),
        raw.get("main_clue"),
        raw.get("sub_clue"),
        raw.get("clue"),
        raw.get("Raw"),
        raw.get("tag_main"),
        raw.get("tags"),
        raw.get("tags_info"),
        raw.get("ti_info"),
        raw,
    ]
    return stringify(fields).lower()


def xmon_owner_src_values(xmon_info: XmonInfo) -> list[str]:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    clues = raw.get("__valid_clues")
    values: list[str] = []
    if isinstance(clues, list):
        for clue in clues:
            if not isinstance(clue, dict):
                continue
            clue_type = normalize_cell(clue.get("__clue_type", ""))
            if clue_type == "main":
                values.append(normalize_cell(clue.get("src", "")))
                continue
            if clue_type == "sub":
                values.append(normalize_cell(clue.get("src", "")))
    return [value.lower() for value in values if value]


def is_url_src(value: str) -> bool:
    text = normalize_cell(value).lower()
    if not text:
        return False
    if text.startswith(("http://", "https://")):
        return True
    parsed = urlparse(text)
    return bool(parsed.scheme and parsed.netloc)


def xmon_owner_candidates(xmon_info: XmonInfo) -> list[str]:
    candidates: list[str] = []
    for value in xmon_owner_src_values(xmon_info):
        if "atateam" in value:
            candidates.append("atateam")
        if "siyubo" in value or value == "netlab.dga":
            candidates.append("siyubo")
        if "wd" in value:
            candidates.append("wd")
        if "btmon" in value or is_url_src(value):
            candidates.append("netlab")
    return list(dict.fromkeys(candidates))


def pick_owner_candidate(candidates: list[str]) -> str:
    candidate_set = set(candidates)
    for owner in OWNER_PRIORITY:
        if owner in candidate_set:
            return owner
    return "unknown"


def collect_owner_candidates(
    xmon_info: XmonInfo,
    wfy_info: dict[str, Any],
    wd_info: WdInfo,
    sc_malicious: bool = False,
) -> list[str]:
    if wfy_is_white(wfy_info):
        return ["unknown"]
    candidates = xmon_owner_candidates(xmon_info)
    if wd_info.malicious and wd_info.has_snapshot:
        candidates.append("wd")
    if sc_malicious:
        candidates.append("netlab")
    text = all_xmon_text(xmon_info)
    if "netlab" in text:
        candidates.append("netlab")
    if not candidates:
        candidates.append("unknown")
    return list(dict.fromkeys(candidates))


def classify_owner(xmon_info: XmonInfo, wfy_info: dict[str, Any], wd_info: WdInfo, sc_malicious: bool = False) -> str:
    candidates = collect_owner_candidates(xmon_info, wfy_info, wd_info, sc_malicious)
    return pick_owner_candidate(candidates)


def has_wd_malicious_snapshot(wd_info: WdInfo) -> bool:
    return wd_info.malicious and wd_info.has_snapshot


def extract_xmon_description(xmon_info: XmonInfo) -> str:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    tag_main = raw.get("tag_main") if isinstance(raw.get("tag_main"), dict) else {}
    description = first_not_empty(tag_main.get("description"))
    if description:
        return description

    child_rows = raw.get("__tagmon_children")
    if isinstance(child_rows, list):
        for child in child_rows:
            if not isinstance(child, dict):
                continue
            exts = child.get("exts") if isinstance(child.get("exts"), dict) else {}
            ioctag = exts.get("ioctag") if isinstance(exts.get("ioctag"), dict) else {}
            description = first_not_empty(ioctag.get("description"))
            if description:
                return description
    return ""


def wd_snapshot_rule_description(description: str) -> str:
    text = normalize_cell(description)
    if text.startswith("钓鱼欺诈"):
        return "钓鱼欺诈"
    return ""


def is_wd_snapshot_rule_hit(xmon_info: XmonInfo, wd_info: WdInfo) -> bool:
    return has_wd_malicious_snapshot(wd_info) and bool(wd_snapshot_rule_description(extract_xmon_description(xmon_info)))


def resolve_wd_snapshot_topic(ioc: str, wd_info: WdInfo, state: PipelineState) -> str:
    title = normalize_cell(wd_info.snapshot_title)
    if title:
        return title
    topic, error = query_wd_snapshot_llm_topic(ioc, wd_info.snapshot_content)
    if error:
        state.wd_llm_failed_iocs.append(f"{ioc} | wd 快照主题大模型总结失败：{error}")
    return topic


def format_wd_snapshot_info_add(description: str, topic: str) -> str:
    return f"内容类存在恶意快照的ioc,描述信息：{description}，主题内容：{topic}"


def finalize_decision(decision: RowDecision) -> RowDecision:
    if decision.solution in {"无更多依据关联", "wfy未报告恶意", "wfy白"}:
        decision.solvable = "否"
    elif decision.solution in {
        "存在黑样本关联",
        "存在关联报告关联",
        "atateam证据链",
        "src是wd且有快照",
        "siyubo证据链",
        "智能体证据链",
    }:
        decision.solvable = "能"
    else:
        decision.solvable = "预解决"
    return decision


def fill_file_features(decision: RowDecision, file_hash: str, hash_info: HashInfo) -> None:
    decision.file_hash = file_hash
    decision.file_size = format_file_size(hash_info.file_size)
    decision.file_type = hash_info.file_type
    decision.operating_system = hash_info.operating_system
    decision.create_time = hash_info.first_seen_time
    decision.other_file_feature = hash_info.other_file_feature


def summarize_evidence_details(details: list[str], limit: int = 50) -> str:
    cleaned: list[str] = []
    for detail in details:
        text = normalize_cell(detail)
        if not text:
            continue
        text = re.sub(r"\s+", "", text)
        text = text.replace("→", "，")
        cleaned.append(text)
    if not cleaned:
        return ""
    summary = "；".join(dict.fromkeys(cleaned))
    return summary[:limit]


def has_black_hash_evidence(xmon_info: XmonInfo, hash_map: dict[str, HashInfo]) -> bool:
    return any(risk_is_black(hash_map.get(ref_hash, HashInfo(query_hash=ref_hash)).risk) for ref_hash in extract_hashes_from_xmon_info(xmon_info))


def ai_evidence_hit_rule(external_info: ExternalIocInfo | None = None) -> str:
    if external_info and external_info.hit_rule:
        return external_info.hit_rule
    return "智能体证据链"


def decide_row(
    row: dict[str, Any],
    xmon_info: XmonInfo,
    hash_map: dict[str, HashInfo],
    wfy_info: dict[str, Any],
    wd_info: WdInfo,
    ai_info: AiInfo | None = None,
    external_info: ExternalIocInfo | None = None,
    atateam_evidence_summary: str = "",
    siyubo_evidence_summary: str = "",
    sc_malicious: bool = False,
    state: PipelineState | None = None,
) -> RowDecision:
    ioc = normalize_cell(row.get("ioc", ""))
    abnormal_input = bool(row.get("__intellens_abnormal_row", False))
    decision = RowDecision(
        ioc=ioc,
        result_ioc=result_ioc(row),
        port=normalize_cell(row.get("端口", "")),
        out_date=normalize_cell(row.get("外联日期", "")),
        alive_status="失活" if wfy_is_unknown(wfy_info) else map_wfy_status(wfy_info.get("status")),
        abnormal_input=abnormal_input,
    )
    if abnormal_input:
        decision.vendor = ""
        decision.alive_status = ""
        decision.owner = ""
        decision.solvable = ""
        decision.solution = ""
        decision.rule_hit = "no_more_evidence"
        decision.hit_rule = ""
        return decision

    ref_hashes = extract_hashes_from_xmon_info(xmon_info)
    first_hash_info = HashInfo(query_hash=ref_hashes[0]) if ref_hashes else HashInfo()
    black_hash = ""
    black_hash_info = HashInfo()
    for ref_hash in ref_hashes:
        hash_info = hash_map.get(ref_hash, HashInfo(query_hash=ref_hash))
        if risk_is_black(hash_info.risk):
            black_hash = ref_hash
            black_hash_info = hash_info
            break
        if not first_hash_info.risk:
            first_hash_info = hash_info

    first_report = pick_first_report(xmon_info.report_links)
    wd_snapshot = has_wd_malicious_snapshot(wd_info)
    decision.owner = classify_owner(xmon_info, wfy_info, wd_info, sc_malicious)

    if wfy_is_white(wfy_info):
        decision.k01_result = "误报"
        decision.info_add = "白名单情报"
        decision.solvable = "否"
        decision.solution = "wfy白"
        decision.rule_hit = "wfy_white"
        decision.hit_rule = "wfy白"
        return finalize_decision(decision)

    if black_hash:
        decision.k01_result = "有效"
        fill_file_features(decision, black_hash, black_hash_info)
        decision.info_add = f"{decision.ioc}，依据ioc({decision.ioc}),关联样本（{black_hash}）"
        decision.solvable = "能"
        decision.solution = "存在黑样本关联"
        decision.rule_hit = "black_hash"
        decision.hit_rule = "存在黑样本关联"
        return finalize_decision(decision)

    if first_report:
        decision.k01_result = "有效"
        decision.info_add = f"{decision.ioc}，依据ioc({decision.ioc}),关联报告（{first_report}）"
        decision.solvable = "能"
        decision.solution = "存在关联报告关联"
        decision.rule_hit = "report"
        decision.hit_rule = "存在关联报告关联"
        return finalize_decision(decision)

    if decision.owner == "atateam":
        evidence_summary = normalize_cell(atateam_evidence_summary)
        if evidence_summary:
            decision.k01_result = "有效"
            decision.info_add = evidence_summary
            decision.solvable = "能"
            decision.solution = "atateam证据链"
            decision.rule_hit = "atateam_evidence_chain"
            decision.hit_rule = "atateam证据链"
            return finalize_decision(decision)

    if decision.owner == "siyubo":
        evidence_summary = normalize_cell(siyubo_evidence_summary)
        if evidence_summary:
            decision.k01_result = "有效"
            decision.info_add = evidence_summary
            decision.solvable = "能"
            decision.solution = "siyubo证据链"
            decision.rule_hit = "siyubo_evidence_chain"
            decision.hit_rule = "siyubo证据链"
            return finalize_decision(decision)

    if decision.owner == "wd" and wd_snapshot:
        rule_description = wd_snapshot_rule_description(extract_xmon_description(xmon_info))
        if rule_description:
            topic = resolve_wd_snapshot_topic(decision.ioc, wd_info, state) if state is not None else ""
            decision.k01_result = "有效"
            decision.info_add = format_wd_snapshot_info_add(rule_description, topic)
            decision.solvable = "能"
            decision.solution = "src是wd且有快照"
            decision.rule_hit = "wd_snapshot"
            decision.hit_rule = "src是wd且有快照"
            return finalize_decision(decision)

    if ai_info and ai_info.summary:
        hit_rule = ai_evidence_hit_rule(external_info)
        decision.k01_result = "有效"
        decision.info_add = ai_info.summary
        decision.solution = hit_rule
        decision.rule_hit = "ai_evidence_chain"
        decision.hit_rule = hit_rule
        return finalize_decision(decision)

    decision.k01_result = ""
    decision.solvable = "否"
    decision.solution = "无更多依据关联"
    decision.rule_hit = "no_more_evidence"
    return finalize_decision(decision)


def print_debug_ioc(
    ioc: str,
    xmon_info: XmonInfo,
    hash_map: dict[str, HashInfo],
    wfy_info: dict[str, Any],
    wd_info: WdInfo,
    sc_malicious: bool,
    decision: RowDecision,
) -> None:
    if ioc not in DEBUG_IOCS and decision.result_ioc not in DEBUG_IOCS:
        return
    ref_hashes = extract_hashes_from_xmon_info(xmon_info)
    hash_risks = {h: normalize_cell(hash_map.get(h, HashInfo(query_hash=h)).risk) for h in ref_hashes}
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    valid_clues = raw.get("__valid_clues")
    valid_clue_count = len(valid_clues) if isinstance(valid_clues, list) else 0
    print("\n[DEBUG] IOC 研判链路")
    print(f"    ioc: {ioc}")
    print(f"    xmon_ioc_search: {xmon_info.ioc_search}")
    print(f"    valid_clues: {valid_clue_count}")
    print(f"    ref_hashes: {ref_hashes}")
    print(f"    hash_risks: {hash_risks}")
    print(f"    wfy_judge: {normalize_cell(wfy_info.get('judge', ''))}")
    print(f"    wd: malicious={wd_info.malicious}, snapshot={wd_info.has_snapshot}")
    print(f"    sc_malicious: {sc_malicious}")
    print(f"    rule_hit: {decision.rule_hit}")
    print(f"    hit_rule: {decision.hit_rule}")
    print(f"    result: {decision.k01_result}")
    print(f"    info_add: {decision.info_add}")


def decision_to_result_row(decision: RowDecision) -> dict[str, str]:
    if decision.abnormal_input:
        return {
            "IOC": decision.result_ioc,
            "端口": decision.port,
            "厂商": "",
            "外联日期": decision.out_date,
            "研判结果": "",
            "存活状态": "",
            "文件特征值": "",
            "文件大小": "",
            "文件类型": "",
            "影响操作系统": "",
            "创建时间": "",
            "相关进程ID及文件名称": "",
            "ICP连接记录": "",
            "HTTP访问记录": "",
            "流量特征": "",
            "其他文件特征": "",
            "补充信息": "",
            "误报原因": "",
            "命中规则": "",
            "拼接后的ioc": "",
        }
    return {
        "IOC": decision.result_ioc,
        "端口": decision.port,
        "厂商": decision.vendor,
        "外联日期": decision.out_date,
        "研判结果": decision.k01_result,
        "存活状态": decision.alive_status,
        "文件特征值": decision.file_hash,
        "文件大小": decision.file_size,
        "文件类型": decision.file_type,
        "影响操作系统": decision.operating_system,
        "创建时间": decision.create_time,
        "相关进程ID及文件名称": "",
        "ICP连接记录": "",
        "HTTP访问记录": "",
        "流量特征": "",
        "其他文件特征": decision.other_file_feature,
        "补充信息": decision.info_add,
        "误报原因": "",
        "命中规则": decision.hit_rule,
        "拼接后的ioc": decision.ioc,
    }


def decision_to_analysis_row(decision: RowDecision) -> dict[str, str]:
    if decision.abnormal_input:
        return {
            "ioc外联目标": decision.result_ioc,
            "端口": decision.port,
            "厂商": "",
            "ioc": "",
            "生产方归属": "",
            "能否解决": "",
            "相关解决方案": "",
        }
    return {
        "ioc外联目标": decision.result_ioc,
        "端口": decision.port,
        "厂商": decision.vendor,
        "ioc": decision.ioc,
        "生产方归属": decision.owner,
        "能否解决": decision.solvable,
        "相关解决方案": decision.solution,
    }


def dedupe_decisions_by_ioc(decisions: list[RowDecision]) -> list[RowDecision]:
    deduped: list[RowDecision] = []
    seen: set[str] = set()
    for decision in decisions:
        key = decision.ioc
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        deduped.append(decision)
    return deduped


def build_analysis_summary_rows(decisions: list[RowDecision], wfy_map: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    deduped_decisions = dedupe_decisions_by_ioc(decisions)
    today_alert_count = len(decisions)
    unique_ioc_count = len({decision.ioc for decision in deduped_decisions if decision.ioc})
    unique_iocs = list(dict.fromkeys(decision.ioc for decision in deduped_decisions if decision.ioc))
    wfy_black_count = sum(1 for ioc in unique_iocs if wfy_is_black(wfy_map.get(ioc, {})))
    wfy_white_count = sum(1 for ioc in unique_iocs if wfy_is_white(wfy_map.get(ioc, {})))
    wfy_unknown_count = len(unique_iocs) - wfy_black_count - wfy_white_count

    black_hash_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "存在黑样本关联")
    report_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "存在关联报告关联")
    atateam_evidence_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "atateam证据链")
    siyubo_evidence_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "siyubo证据链")
    wd_snapshot_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "src是wd且有快照")
    ai_evidence_count = sum(1 for decision in deduped_decisions if decision.hit_rule == "智能体证据链")
    external_wb_evidence_count = sum(1 for decision in deduped_decisions if decision.hit_rule == EXTERNAL_WB_HIT_RULE)
    external_qax_evidence_count = sum(1 for decision in deduped_decisions if decision.hit_rule == EXTERNAL_QAX_HIT_RULE)

    remaining_decisions = [
        decision
        for decision in deduped_decisions
        if decision.rule_hit == "no_more_evidence" and not wfy_is_white(wfy_map.get(decision.ioc, {}))
    ]
    remaining_count = len(remaining_decisions)
    owner_counter = Counter(decision.owner if decision.owner in OWNER_PRIORITY else "unknown" for decision in deduped_decisions)
    owner_total = sum(owner_counter.get(owner, 0) for owner in OWNER_PRIORITY)
    owner_text = "，".join(
        f"{owner}（{owner_counter.get(owner, 0)}条）"
        for owner in ("atateam", "siyubo", "wd", "netlab", "unknown")
    )
    non_ai_decisions = [decision for decision in deduped_decisions if decision.solution != "智能体证据链"]
    non_ai_owner_counter = Counter(decision.owner if decision.owner in OWNER_PRIORITY else "unknown" for decision in non_ai_decisions)
    non_ai_owner_total = sum(non_ai_owner_counter.get(owner, 0) for owner in OWNER_PRIORITY)
    non_ai_owner_text = "，".join(
        f"{owner}（{non_ai_owner_counter.get(owner, 0)}/{owner_counter.get(owner, 0)}条）"
        for owner in ("atateam", "siyubo", "wd", "netlab", "unknown")
    )

    lines = [
        f"今日告警数量：{today_alert_count}",
        f"拼接后ioc去重数量：{unique_ioc_count}",
        f"wfy黑{wfy_black_count}条，白{wfy_white_count}条，unknown/空返回{wfy_unknown_count}条",
        f"hash黑样本命中{black_hash_count}",
        f"report_links命中{report_count}",
        f"atateam证据链{atateam_evidence_count}",
        f"siyubo证据链{siyubo_evidence_count}",
        f"wd存在快照{wd_snapshot_count}",
        f"外部wb接口证据链{external_wb_evidence_count}",
        f"外部qax接口证据链{external_qax_evidence_count}",
        f"智能体证据链{ai_evidence_count}",
        f"还剩余{remaining_count}条ioc",
        f"拼接ioc去重后生产方归属总计{owner_total}条，{owner_text}",
        f"拼接ioc去重后，排除智能体证据链后，生产方归属总计{non_ai_owner_total}/{owner_total}条；\n"
        f"生产方对应已解决情况：{non_ai_owner_text}；",
    ]
    return [{"序号": str(index), "统计信息": line} for index, line in enumerate(lines, 1)]
