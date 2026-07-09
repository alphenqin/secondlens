"""IntelLens 智能体证据链：AI quick analysis + AI LLM 摘要增强。
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import AiInfo
from app.intellens.clients.llm import (
    build_llm_chat_payload,
    format_llm_evidence_bullets,
    normalize_ai_llm_summary_with_reason,
    query_llm_chat_summary,
)


def query_ai_quick_analysis_one(ioc: str) -> AiInfo:
    payload = {
        "ioc": ioc,
        "ioc_type": "domain",
    }
    data: Any = {}
    last_error = ""
    max_attempts = AI_RETRIES + 1
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(AI_RETRY_SLEEP_SECONDS * (attempt - 1))
        try:
            session = get_thread_session()
            resp = session.post(
                AI_QUICK_ANALYSIS_URL,
                headers=AI_QUICK_ANALYSIS_HEADERS,
                data=json_utf8_body(payload),
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = safe_json_response(resp)
            break
        except Exception as exc:
            last_error = str(exc)
    else:
        return AiInfo(ioc=ioc, query_error=last_error)

    body = data.get("data") if isinstance(data, dict) else {}
    key_evidence = body.get("key_evidence", []) if isinstance(body, dict) else []
    if not isinstance(key_evidence, list):
        key_evidence = []
    filtered = [
        normalize_cell(item)
        for item in key_evidence
        if normalize_cell(item) and not any(term in normalize_cell(item) for term in AI_KEY_EVIDENCE_DROP_TERMS)
    ]
    return AiInfo(ioc=ioc, key_evidence=filtered)


def query_ai_evidence_llm_summary_one(ioc: str, details: list[str]) -> tuple[str, str, str]:
    cleaned_details = [normalize_cell(detail) for detail in details if normalize_cell(detail)]
    if not cleaned_details:
        return ioc, "", ""
    payload = build_llm_chat_payload(
        "你是安全情报分析助手，只输出最终研判依据，不要解释。",
        f"{AI_EVIDENCE_PROMPT}\n\n" + format_llm_evidence_bullets(cleaned_details),
    )
    summary, error = query_llm_chat_summary(payload)
    normalized_summary, reject_reason = normalize_ai_llm_summary_with_reason(summary)
    if reject_reason and not error:
        raw_summary = normalize_cell(summary)
        evidence_text = "；".join(cleaned_details)
        return ioc, "", f"SUMMARY_REJECTED:{reject_reason}：{raw_summary} | 智能体证据链：{evidence_text}"
    return ioc, normalized_summary, error


def enrich_ai_infos_with_llm_summaries(result_map: dict[str, AiInfo], state: PipelineState) -> dict[str, AiInfo]:
    candidates = {ioc: info.key_evidence for ioc, info in result_map.items() if info.key_evidence}
    if not candidates:
        return result_map
    if not LLM_TOKEN:
        print("[!] 未配置 LLM_TOKEN，跳过智能体证据链大模型总结。")
        return result_map

    print(f"[+] 智能体证据链大模型总结待处理：{len(candidates)} 条，并发数 {min(LLM_WORKERS, len(candidates))}")
    if LLM_WORKERS <= 1 or len(candidates) == 1:
        for index, (ioc, details) in enumerate(candidates.items(), 1):
            _, summary, error = query_ai_evidence_llm_summary_one(ioc, details)
            if error:
                if error.startswith("SUMMARY_REJECTED:"):
                    state.ai_llm_rejected_summaries.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    state.ai_failed_iocs.append(f"{ioc} | 智能体证据链大模型总结失败：{error}")
            if summary:
                result_map[ioc].summary = summary
            if index % AI_PROGRESS_INTERVAL == 0 or index == len(candidates):
                print(f"[+] 智能体证据链大模型总结进度：{index}/{len(candidates)}")
            time.sleep(SLEEP_SECONDS)
        return result_map

    worker_count = min(LLM_WORKERS, len(candidates))
    completed = 0
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(query_ai_evidence_llm_summary_one, ioc, details): ioc
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
                    state.ai_llm_rejected_summaries.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
                else:
                    state.ai_failed_iocs.append(f"{ioc} | 智能体证据链大模型总结失败：{error}")
            if summary:
                result_map[ioc].summary = summary
            if completed % AI_PROGRESS_INTERVAL == 0 or completed == len(candidates):
                print(f"[+] 智能体证据链大模型总结进度：{completed}/{len(candidates)}")
    return result_map


def query_ai_quick_analysis(ioc_list: list[str], state: PipelineState) -> dict[str, AiInfo]:
    unique_iocs = list(dict.fromkeys(ioc for ioc in ioc_list if ioc))
    result_map: dict[str, AiInfo] = {}
    if not unique_iocs:
        return result_map
    ai_worker_count = min(max(AI_WORKERS, 1), len(unique_iocs))
    llm_worker_count = min(max(LLM_WORKERS, 1), len(unique_iocs))
    print(f"[+] 智能体证据链待查询：{len(unique_iocs)} 条，并发数 {ai_worker_count}")
    if not LLM_TOKEN:
        print("[!] 未配置 LLM_TOKEN，跳过智能体证据链大模型总结。")

    completed = 0
    llm_completed = 0
    llm_future_map: dict[Any, str] = {}

    def print_ai_pipeline_progress(force: bool = False) -> None:
        llm_submitted = llm_completed + len(llm_future_map)
        if force or completed % AI_PROGRESS_INTERVAL == 0 or completed == len(unique_iocs):
            print(
                f"[+] 智能体证据链完成 {completed}/{len(unique_iocs)}，"
                f"大语言模型总结已提交 {llm_submitted}，"
                f"大语言模型总结已完成 {llm_completed}"
            )

    def collect_llm_future(future: Any, ioc: str) -> None:
        nonlocal llm_completed
        llm_completed += 1
        try:
            _, summary, error = future.result()
        except Exception as exc:
            summary = ""
            error = str(exc)
        if error:
            if error.startswith("SUMMARY_REJECTED:"):
                state.ai_llm_rejected_summaries.append(f"{ioc} | {error.removeprefix('SUMMARY_REJECTED:')}")
            else:
                state.ai_failed_iocs.append(f"{ioc} | 智能体证据链大模型总结失败：{error}")
        if summary:
            result_map[ioc].summary = summary

    def collect_completed_llm_results() -> None:
        for llm_future, ioc in list(llm_future_map.items()):
            if not llm_future.done():
                continue
            collect_llm_future(llm_future, ioc)
            del llm_future_map[llm_future]

    def collect_ai_results(llm_executor: ThreadPoolExecutor | None = None) -> None:
        nonlocal completed
        with ThreadPoolExecutor(max_workers=ai_worker_count) as ai_executor:
            future_map = {ai_executor.submit(query_ai_quick_analysis_one, ioc): ioc for ioc in unique_iocs}
            for future in as_completed(future_map):
                ioc = future_map[future]
                completed += 1
                try:
                    info = future.result()
                except Exception as exc:
                    info = AiInfo(ioc=ioc, query_error=str(exc))
                if info.query_error:
                    state.ai_failed_iocs.append(f"{ioc} | {info.query_error}")
                result_map[ioc] = info
                if llm_executor and info.key_evidence:
                    llm_future = llm_executor.submit(query_ai_evidence_llm_summary_one, ioc, info.key_evidence)
                    llm_future_map[llm_future] = ioc
                collect_completed_llm_results()
                print_ai_pipeline_progress()

    if LLM_TOKEN:
        print(f"[+] 智能体证据链大模型总结采用流水线，并发数 {llm_worker_count}")
        with ThreadPoolExecutor(max_workers=llm_worker_count) as llm_executor:
            collect_ai_results(llm_executor)
            print_ai_pipeline_progress(force=True)
            for future in as_completed(list(llm_future_map)):
                ioc = llm_future_map.pop(future)
                collect_llm_future(future, ioc)
                if llm_completed % AI_PROGRESS_INTERVAL == 0 or not llm_future_map:
                    print_ai_pipeline_progress(force=True)
    else:
        collect_ai_results()
    return result_map
