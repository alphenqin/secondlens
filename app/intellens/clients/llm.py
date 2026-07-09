from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import XmonInfo


def format_llm_evidence_bullets(details: list[str]) -> str:
    lines: list[str] = []
    for detail in dict.fromkeys(normalize_cell(item) for item in details):
        if not detail:
            continue
        lines.append(f"- {detail}")
    return "\n".join(lines)


def extract_siyubo_evidence_details(xmon_info: XmonInfo) -> list[str]:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    clues = raw.get("__valid_clues")
    details: list[str] = []
    if not isinstance(clues, list):
        return []
    for clue in clues:
        if not isinstance(clue, dict):
            continue
        if normalize_cell(clue.get("__clue_type", "")) != "sub":
            continue
        exts = clue.get("exts") if isinstance(clue.get("exts"), dict) else {}
        raw_data = exts.get("_raw") if isinstance(exts.get("_raw"), dict) else {}
        ext = raw_data.get("ext") if isinstance(raw_data.get("ext"), dict) else {}
        evidence_chain = ext.get("evidence_chain")
        if not isinstance(evidence_chain, list):
            continue
        for item in evidence_chain:
            if isinstance(item, dict):
                detail = normalize_cell(item.get("detail", ""))
                if detail:
                    details.append(detail)
    return list(dict.fromkeys(details))


def extract_atateam_evidence_ext(xmon_info: XmonInfo) -> dict[str, Any]:
    raw = xmon_info.raw if isinstance(xmon_info.raw, dict) else {}
    child_rows = raw.get("__tagmon_children")
    if not isinstance(child_rows, list):
        return {}
    for child in child_rows:
        if not isinstance(child, dict):
            continue
        exts = child.get("exts") if isinstance(child.get("exts"), dict) else {}
        src = normalize_cell(first_not_empty(child.get("src"), exts.get("src", "")))
        if src.lower() != "apt.atateam":
            continue
        raw_data = exts.get("_raw") if isinstance(exts.get("_raw"), dict) else {}
        ext = raw_data.get("ext") if isinstance(raw_data.get("ext"), dict) else {}
        if ext:
            return ext
    return {}


def strip_llm_summary_text(value: Any) -> str:
    text = normalize_cell(value)
    if not text:
        return ""
    text = re.sub(r"^```(?:text)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    return text.strip("\"'“”‘’")


def normalize_siyubo_llm_summary_with_reason(summary: str) -> tuple[str, str]:
    text = strip_llm_summary_text(summary)
    if not text:
        return "", "大模型返回空"
    if any(term in text for term in SIYUBO_NO_RESULT_TERMS) and not any(term in text for term in SIYUBO_HIT_TERMS):
        return "", "大模型判定无法形成恶意或可疑依据"
    return text, ""


def mask_china_attribution(text: str) -> str:
    replacements = (
        "疑似中国国家背景攻击组织",
        "中国国家背景攻击组织",
        "疑似中国攻击组织",
        "中国攻击组织",
        "中国关联APT组织",
        "中国关联APT",
        "中国APT组织",
        "中国APT",
        "中国关联组织",
        "中国背景攻击组织",
        "中国背景组织",
        "中国国家背景",
        "中国攻击背景",
        "中国关联",
        "中国来源",
        "China-nexus",
        "China-linked",
        "Chinese state-sponsored",
        "Chinese state sponsored",
        "Chinese APT",
        "China APT",
        "PRC-linked",
        "PRC sponsored",
        "PRC-sponsored",
        "PRC",
        "Chinese",
        "China",
        "中国",
    )
    masked = text
    for value in replacements:
        masked = masked.replace(value, "国家级背景攻击实体")
    masked = re.sub(r"(国家级背景攻击实体)(?:[\s、，,-]*(国家级背景攻击实体))+", "国家级背景攻击实体", masked)
    return masked


def normalize_atateam_llm_summary_with_reason(summary: str) -> tuple[str, str]:
    text = strip_llm_summary_text(summary)
    if not text:
        return "", "大模型返回空"
    if any(term in text for term in ATATEAM_NO_RESULT_TERMS):
        return "", "大模型判定无法形成恶意或可疑依据"
    return mask_china_attribution(text), ""


def normalize_ai_llm_summary_with_reason(summary: str) -> tuple[str, str]:
    text = strip_llm_summary_text(summary)
    if not text:
        return "", "大模型返回空"
    if any(term in text for term in AI_NO_RESULT_TERMS):
        return "", "包含无法形成依据相关词"
    if any(term in text for term in AI_REFUSAL_TERMS):
        return "", "大模型返回拒答套话"
    return text, ""


def parse_llm_summary_response(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    choices = data.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            message = first.get("message")
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    return content
            text = first.get("text")
            if isinstance(text, str):
                return text
    output_text = data.get("output_text")
    if isinstance(output_text, str):
        return output_text
    body = data.get("data")
    if isinstance(body, dict):
        summary = first_not_empty(body.get("summary"), body.get("content"), body.get("text"))
        if summary:
            return summary
    return ""


def query_llm_chat_summary(payload: dict[str, Any]) -> tuple[str, str]:
    if not LLM_TOKEN:
        return "", "missing LLM_TOKEN"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LLM_TOKEN}",
    }
    last_error = ""
    max_attempts = LLM_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(LLM_RETRY_SLEEP_SECONDS * (attempt - 1))
        try:
            session = get_thread_session()
            resp = session.post(
                LLM_API_URL,
                headers=headers,
                data=json_utf8_body(payload),
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return parse_llm_summary_response(safe_json_response(resp)), ""
        except Exception as exc:
            last_error = str(exc)
    return "", last_error


def build_llm_chat_payload(system_content: str, user_content: str) -> dict[str, Any]:
    return {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": system_content},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0,
        "max_tokens": LLM_SUMMARY_MAX_TOKENS,
    }


def normalize_wd_snapshot_llm_topic(topic: str) -> str:
    return strip_llm_summary_text(topic)


def query_wd_snapshot_llm_topic(ioc: str, content: str) -> tuple[str, str]:
    text = normalize_cell(content)
    if not text:
        return "", ""
    if ioc in WD_SNAPSHOT_TOPIC_SUMMARY_CACHE:
        return WD_SNAPSHOT_TOPIC_SUMMARY_CACHE[ioc], ""
    payload = build_llm_chat_payload(
        "你是安全情报分析助手，只输出最终主题内容，不要解释。",
        (
            "以下是恶意快照页面内容。请总结快照主题内容，50字以内。"
            "不要输出前缀、编号或解释。\n\n"
            f"快照内容如下：\n{text[:4000]}"
        ),
    )
    topic, error = query_llm_chat_summary(payload)
    normalized_topic = normalize_wd_snapshot_llm_topic(topic)
    if normalized_topic:
        WD_SNAPSHOT_TOPIC_SUMMARY_CACHE[ioc] = normalized_topic
    return normalized_topic, error


def query_siyubo_llm_summary_one(ioc: str, details: list[str]) -> tuple[str, str, str]:
    if not LLM_TOKEN:
        return ioc, "", "missing LLM_TOKEN"
    cleaned_details = [normalize_cell(detail) for detail in details if normalize_cell(detail)]
    if not cleaned_details:
        return ioc, "", ""

    payload = build_llm_chat_payload(
        "你是安全情报分析助手，只输出最终研判依据，不要解释。",
        (
            f"{SIYUBO_EVIDENCE_PROMPT}\n\n"
            "evidence_chain detail如下：\n"
            + format_llm_evidence_bullets(cleaned_details)
        ),
    )
    summary, error = query_llm_chat_summary(payload)
    normalized_summary, reject_reason = normalize_siyubo_llm_summary_with_reason(summary)
    if reject_reason and not error:
        raw_summary = normalize_cell(summary)
        evidence_text = "；".join(cleaned_details)
        return ioc, "", f"SUMMARY_REJECTED:{reject_reason}：{raw_summary} | siyubo证据链：{evidence_text}"
    return ioc, normalized_summary, error


def query_siyubo_llm_summaries(evidence_map: dict[str, list[str]], state: PipelineState, max_workers: int | None = None) -> dict[str, str]:
    candidates = {ioc: details for ioc, details in evidence_map.items() if details}
    if not candidates:
        return {}
    if not LLM_TOKEN:
        print("[!] 未配置 LLM_TOKEN，跳过 siyubo evidence_chain 大模型总结，继续后续智能体证据链规则。")
        return {}

    configured_workers = LLM_WORKERS if max_workers is None else max(1, max_workers)
    print(f"[+] siyubo evidence_chain 大模型总结待处理：{len(candidates)} 条，并发数 {min(configured_workers, len(candidates))}")
    result_map: dict[str, str] = {}
    if configured_workers <= 1 or len(candidates) == 1:
        for index, (ioc, details) in enumerate(candidates.items(), 1):
            _, summary, error = query_siyubo_llm_summary_one(ioc, details)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    state.siyubo_llm_rejected_summaries.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    state.siyubo_llm_failed_iocs.append(f"{ioc} | siyubo evidence_chain 大模型总结失败：{error}")
            if summary:
                result_map[ioc] = summary
            if index % AI_PROGRESS_INTERVAL == 0 or index == len(candidates):
                print(f"[+] siyubo evidence_chain 大模型总结进度：{index}/{len(candidates)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(configured_workers, len(candidates))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_siyubo_llm_summary_one, ioc, details): ioc
            for ioc, details in candidates.items()
        }
        for future in as_completed(future_map):
            ioc = future_map[future]
            completed += 1
            try:
                _, summary, error = future.result()
            except Exception as exc:
                summary = ""
                error = str(exc)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    state.siyubo_llm_rejected_summaries.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    state.siyubo_llm_failed_iocs.append(f"{ioc} | siyubo evidence_chain 大模型总结失败：{error}")
            if summary:
                result_map[ioc] = summary
            if completed % AI_PROGRESS_INTERVAL == 0 or completed == len(candidates):
                print(f"[+] siyubo evidence_chain 大模型总结进度：{completed}/{len(candidates)}")
    return result_map


def query_atateam_llm_summary_one(ioc: str, ext: dict[str, Any]) -> tuple[str, str, str]:
    if not LLM_TOKEN:
        return ioc, "", "missing LLM_TOKEN"
    if not ext:
        return ioc, "", ""
    ext_json = json.dumps(ext, ensure_ascii=False, sort_keys=True)
    payload = build_llm_chat_payload(
        "你是安全情报分析助手，只输出最终研判依据，不要解释。",
        (
            f"{ATATEAM_EVIDENCE_PROMPT}\n\n"
            "atateam evidence_chain JSON如下：\n"
            f"- {ext_json}"
        ),
    )
    summary, error = query_llm_chat_summary(payload)
    normalized_summary, reject_reason = normalize_atateam_llm_summary_with_reason(summary)
    if reject_reason and not error:
        raw_summary = normalize_cell(summary)
        return ioc, "", f"SUMMARY_REJECTED:{reject_reason}：{raw_summary} | atateam证据链：{ext_json}"
    return ioc, normalized_summary, error


def query_atateam_llm_summaries(evidence_map: dict[str, dict[str, Any]], state: PipelineState, max_workers: int | None = None) -> dict[str, str]:
    candidates = {ioc: ext for ioc, ext in evidence_map.items() if ext}
    if not candidates:
        return {}
    if not LLM_TOKEN:
        print("[!] 未配置 LLM_TOKEN，跳过 atateam evidence_chain 大模型总结，继续后续规则。")
        return {}

    configured_workers = LLM_WORKERS if max_workers is None else max(1, max_workers)
    print(f"[+] atateam evidence_chain 大模型总结待处理：{len(candidates)} 条，并发数 {min(configured_workers, len(candidates))}")
    result_map: dict[str, str] = {}
    if configured_workers <= 1 or len(candidates) == 1:
        for index, (ioc, ext) in enumerate(candidates.items(), 1):
            _, summary, error = query_atateam_llm_summary_one(ioc, ext)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    state.atateam_llm_rejected_summaries.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    state.atateam_llm_failed_iocs.append(f"{ioc} | atateam evidence_chain 大模型总结失败：{error}")
            if summary:
                result_map[ioc] = summary
            if index % AI_PROGRESS_INTERVAL == 0 or index == len(candidates):
                print(f"[+] atateam evidence_chain 大模型总结进度：{index}/{len(candidates)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(configured_workers, len(candidates))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_atateam_llm_summary_one, ioc, ext): ioc
            for ioc, ext in candidates.items()
        }
        for future in as_completed(future_map):
            ioc = future_map[future]
            completed += 1
            try:
                _, summary, error = future.result()
            except Exception as exc:
                summary = ""
                error = str(exc)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    state.atateam_llm_rejected_summaries.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    state.atateam_llm_failed_iocs.append(f"{ioc} | atateam evidence_chain 大模型总结失败：{error}")
            if summary:
                result_map[ioc] = summary
            if completed % AI_PROGRESS_INTERVAL == 0 or completed == len(candidates):
                print(f"[+] atateam evidence_chain 大模型总结进度：{completed}/{len(candidates)}")
    return result_map

