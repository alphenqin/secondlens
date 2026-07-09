"""IntelLens IOC 研判流水线：阶段调度、证据/candidate 构造、run_decision_pipeline 编排。"""
from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from app.intellens.config import *  # noqa: F401,F403
from app.intellens.state import *  # noqa: F401,F403
from app.intellens.utils import *  # noqa: F401,F403
from app.intellens.models import AiInfo, ExternalIocInfo, HashInfo, RowDecision, WdInfo, XmonInfo
from app.intellens.clients.hash import extract_hashes_from_xmon_info, query_hashes
from app.intellens.clients.wfy import query_wfy
from app.intellens.clients.sc import query_sc
from app.intellens.clients.wd import query_wd
from app.intellens.clients.xmon import empty_xmon_info, query_xmon_iocs
from app.intellens.clients.external import query_external_ioc_evidence
from app.intellens.clients.ai import query_ai_quick_analysis
from app.intellens.clients.llm import (
    extract_atateam_evidence_ext,
    extract_siyubo_evidence_details,
    query_atateam_llm_summaries,
    query_siyubo_llm_summaries,
)
from app.intellens.decision import (
    classify_owner,
    decide_row,
    has_black_hash_evidence,
    is_wd_snapshot_rule_hit,
    pick_first_report,
    print_debug_ioc,
    risk_is_black,
    wfy_is_black,
    wfy_is_white,
    xmon_owner_candidates,
)


def start_stage(name: str) -> float:
    print(f"\n[+] 开始：{name}")
    return time.time()


def finish_stage(name: str, start_time: float) -> None:
    elapsed = time.time() - start_time
    print(f"[+] 完成：{name}，耗时 {elapsed:.2f} 秒（{elapsed / 60:.2f} 分钟）")


def run_stage(name: str, func: Any) -> Any:
    stage_time = start_stage(name)
    try:
        return func()
    finally:
        finish_stage(name, stage_time)


def run_parallel_stages(stage_funcs: dict[str, Any]) -> dict[str, Any]:
    if not stage_funcs:
        return {}
    names = list(stage_funcs.keys())
    if len(names) > 1:
        print(f"[+] 并行执行：{'、'.join(names)}")
    results: dict[str, Any] = {}
    first_error: Exception | None = None
    with ThreadPoolExecutor(max_workers=len(stage_funcs)) as executor:
        future_map = {executor.submit(run_stage, name, func): name for name, func in stage_funcs.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception as exc:
                # 接口查询失败已在底层 batch 函数内 try 并记录 FAILED_IOCS，不会到达这里；
                # 能到达这里的异常是编排逻辑 bug 或数据结构变化，必须暴露，不能静默成空结果。
                print(f"[!] 阶段「{name}」异常：{exc}")
                if first_error is None:
                    first_error = exc
    if first_error is not None:
        raise first_error
    return results


def build_hash_map_from_xmon(xmon_map: dict[str, XmonInfo], state: PipelineState) -> dict[str, HashInfo]:
    all_hashes: list[str] = []
    for xmon_info in xmon_map.values():
        all_hashes.extend(extract_hashes_from_xmon_info(xmon_info))
    unique_hashes = list(dict.fromkeys(h for h in all_hashes if h))
    print(f"[+] xmon 提取关联 hash：{len(unique_hashes)} 条")
    hash_map = query_hashes(unique_hashes, state)
    risk_counter = Counter(normalize_cell(info.risk).lower() or "empty" for info in hash_map.values())
    print(f"[+] hash risk 统计：{dict(risk_counter)}")
    hash_hit_count = sum(1 for info in hash_map.values() if normalize_cell(info.risk))
    black_hash_count = sum(1 for info in hash_map.values() if risk_is_black(info.risk))
    print(f"[+] hash 文件情报命中：{hash_hit_count}/{len(unique_hashes)}，黑样本 hash：{black_hash_count}")
    return hash_map


def build_wd_candidate_iocs(black_iocs: list[str], xmon_map: dict[str, XmonInfo]) -> list[str]:
    return [
        ioc
        for ioc in black_iocs
        if not {"atateam", "siyubo"}.intersection(xmon_owner_candidates(xmon_map.get(ioc, empty_xmon_info(ioc))))
    ]


def build_atateam_evidence_ext_map(
    black_iocs: list[str],
    xmon_map: dict[str, XmonInfo],
    hash_map: dict[str, HashInfo],
    wfy_map: dict[str, dict[str, Any]],
    sc_map: dict[str, bool],
    wd_map: dict[str, WdInfo],
) -> dict[str, dict[str, Any]]:
    evidence_map: dict[str, dict[str, Any]] = {}
    for ioc in black_iocs:
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
        if owner != "atateam":
            continue
        if has_black_hash_evidence(xmon_info, hash_map):
            continue
        if pick_first_report(xmon_info.report_links):
            continue
        ext = extract_atateam_evidence_ext(xmon_info)
        if ext:
            evidence_map[ioc] = ext
    return evidence_map


def build_siyubo_evidence_details_map(
    black_iocs: list[str],
    xmon_map: dict[str, XmonInfo],
    hash_map: dict[str, HashInfo],
    wfy_map: dict[str, dict[str, Any]],
    sc_map: dict[str, bool],
    wd_map: dict[str, WdInfo],
) -> dict[str, list[str]]:
    evidence_map: dict[str, list[str]] = {}
    for ioc in black_iocs:
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
        if owner != "siyubo":
            continue
        if has_black_hash_evidence(xmon_info, hash_map):
            continue
        if pick_first_report(xmon_info.report_links):
            continue
        details = extract_siyubo_evidence_details(xmon_info)
        if details:
            evidence_map[ioc] = details
    return evidence_map


def split_llm_stage_workers(atateam_count: int, siyubo_count: int) -> tuple[int, int]:
    total = max(1, LLM_WORKERS)
    if atateam_count <= 0 or siyubo_count <= 0:
        return total, total
    # 各自保底 1，剩余按候选数比例分配，保证总和不超过 total
    remaining = max(0, total - 2)
    atateam = 1 + round(remaining * atateam_count / (atateam_count + siyubo_count))
    atateam = min(atateam, atateam_count)
    siyubo = min(total - atateam, siyubo_count)
    return atateam, siyubo


def build_ai_candidate_iocs(
    ioc_list: list[str],
    xmon_map: dict[str, XmonInfo],
    hash_map: dict[str, HashInfo],
    wfy_map: dict[str, dict[str, Any]],
    sc_map: dict[str, bool],
    wd_map: dict[str, WdInfo],
    atateam_summary_map: dict[str, str],
    siyubo_summary_map: dict[str, str],
) -> list[str]:
    ai_candidate_iocs: list[str] = []
    for ioc in ioc_list:
        if wfy_is_white(wfy_map.get(ioc, {})):
            continue
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        if has_black_hash_evidence(xmon_info, hash_map):
            continue
        if pick_first_report(xmon_info.report_links):
            continue
        owner = classify_owner(xmon_info, wfy_info, wd_info, sc_map.get(ioc, False))
        if owner == "wd" and is_wd_snapshot_rule_hit(xmon_info, wd_info):
            continue
        if atateam_summary_map.get(ioc):
            continue
        if siyubo_summary_map.get(ioc):
            continue
        ai_candidate_iocs.append(ioc)
    return ai_candidate_iocs


@dataclass
class PipelineResult:
    """流水线产物。decisions 按 ioc 去重，调用方按需映射回行序或响应项。"""

    decisions: dict[str, RowDecision]
    ai_map: dict[str, AiInfo]
    xmon_map: dict[str, XmonInfo]
    wfy_map: dict[str, dict[str, Any]]
    hash_map: dict[str, HashInfo]
    wd_map: dict[str, WdInfo]
    atateam_summary_map: dict[str, str]
    siyubo_summary_map: dict[str, str]
    external_ioc_map: dict[str, ExternalIocInfo]
    sc_malicious_map: dict[str, bool]
    state: PipelineState


def run_decision_pipeline(
    ioc_list: list[str],
    sc_malicious_map: dict[str, bool] | None = None,
    *,
    enable_retry: bool = False,
    row_map: dict[str, dict[str, Any]] | None = None,
) -> PipelineResult:
    """跑完整研判流水线，返回各阶段产物（含 decisions 按 ioc 去重）。"""
    state = PipelineState()

    stage_time = start_stage("查询 wfy")
    wfy_map = query_wfy(ioc_list, state)
    black_iocs = [ioc for ioc in ioc_list if wfy_is_black(wfy_map.get(ioc, {}))]
    white_iocs = [ioc for ioc in ioc_list if wfy_is_white(wfy_map.get(ioc, {}))]
    rule_iocs = [ioc for ioc in ioc_list if not wfy_is_white(wfy_map.get(ioc, {}))]
    print(f"[+] wfy black IOC：{len(black_iocs)} 条")
    print(f"[+] wfy white IOC：{len(white_iocs)} 条")
    print(f"[+] wfy unknown/空返回继续规则 IOC：{len(rule_iocs) - len(black_iocs)} 条")
    finish_stage("查询 wfy", stage_time)

    sc_map: dict[str, bool]
    first_stage: dict[str, Any] = {"查询 xmon 主线索和子线索": lambda: query_xmon_iocs(ioc_list, state)}
    if rule_iocs and sc_malicious_map is None:
        first_stage["查询 sc"] = lambda: query_sc(rule_iocs, state)
    first_parallel_results = run_parallel_stages(first_stage)
    xmon_map = first_parallel_results["查询 xmon 主线索和子线索"]
    if sc_malicious_map is None:
        sc_map = first_parallel_results.get("查询 sc", {})
    else:
        sc_map = sc_malicious_map

    rule_xmon_map = {ioc: xmon_map.get(ioc, empty_xmon_info(ioc)) for ioc in rule_iocs}
    wd_candidate_iocs = build_wd_candidate_iocs(rule_iocs, xmon_map)
    print(f"[+] wd 候选 IOC：{len(wd_candidate_iocs)} 条")
    second_stage_funcs: dict[str, Any] = {
        "提取并查询 hash 文件情报": lambda: build_hash_map_from_xmon(rule_xmon_map, state),
    }
    if wd_candidate_iocs:
        second_stage_funcs["查询 wd"] = lambda: query_wd(wd_candidate_iocs, state)
    second_parallel_results = run_parallel_stages(second_stage_funcs)
    hash_map = second_parallel_results["提取并查询 hash 文件情报"]
    wd_map = second_parallel_results.get("查询 wd", {})

    atateam_evidence_ext_map = build_atateam_evidence_ext_map(rule_iocs, xmon_map, hash_map, wfy_map, sc_map, wd_map)
    siyubo_evidence_details_map = build_siyubo_evidence_details_map(rule_iocs, xmon_map, hash_map, wfy_map, sc_map, wd_map)
    atateam_workers, siyubo_workers = split_llm_stage_workers(
        len(atateam_evidence_ext_map),
        len(siyubo_evidence_details_map),
    )
    llm_stage_funcs: dict[str, Any] = {}
    if atateam_evidence_ext_map:
        llm_stage_funcs["总结 atateam evidence_chain"] = lambda: query_atateam_llm_summaries(
            atateam_evidence_ext_map,
            state,
            max_workers=atateam_workers,
        )
    if siyubo_evidence_details_map:
        llm_stage_funcs["总结 siyubo evidence_chain"] = lambda: query_siyubo_llm_summaries(
            siyubo_evidence_details_map,
            state,
            max_workers=siyubo_workers,
        )
    if len(llm_stage_funcs) > 1 and LLM_WORKERS <= 1:
        llm_parallel_results = {name: run_stage(name, func) for name, func in llm_stage_funcs.items()}
    else:
        llm_parallel_results = run_parallel_stages(llm_stage_funcs)
    atateam_summary_map = llm_parallel_results.get("总结 atateam evidence_chain", {})
    siyubo_summary_map = llm_parallel_results.get("总结 siyubo evidence_chain", {})
    print(f"[+] atateam evidence_chain 大模型有效总结：{len(atateam_summary_map)} 条")
    print(f"[+] siyubo evidence_chain 大模型有效总结：{len(siyubo_summary_map)} 条")

    ai_candidate_iocs = build_ai_candidate_iocs(
        ioc_list,
        xmon_map,
        hash_map,
        wfy_map,
        sc_map,
        wd_map,
        atateam_summary_map,
        siyubo_summary_map,
    )
    stage_time = start_stage("查询外部接口证据链")
    external_ioc_map = query_external_ioc_evidence(ai_candidate_iocs, state) if ai_candidate_iocs else {}
    finish_stage("查询外部接口证据链", stage_time)

    stage_time = start_stage("查询智能体证据链")
    ai_map = query_ai_quick_analysis(ai_candidate_iocs, state) if ai_candidate_iocs else {}
    if enable_retry:
        print("[!] 当前 secondlens 版本不启用 IntelLens 失败重跑逻辑")
    finish_stage("查询智能体证据链", stage_time)

    stage_time = start_stage("生成研判结果")
    decisions: dict[str, RowDecision] = {}
    for ioc in ioc_list:
        if ioc in decisions:
            continue
        xmon_info = xmon_map.get(ioc, empty_xmon_info(ioc))
        wfy_info = wfy_map.get(ioc, {})
        wd_info = wd_map.get(ioc, WdInfo(ioc=ioc))
        ai_info = ai_map.get(ioc, AiInfo(ioc=ioc))
        external_info = external_ioc_map.get(ioc, ExternalIocInfo(ioc=ioc))
        atateam_evidence_summary = atateam_summary_map.get(ioc, "")
        siyubo_evidence_summary = siyubo_summary_map.get(ioc, "")
        sc_malicious = sc_map.get(ioc, False)
        row = row_map.get(ioc) if row_map is not None else None
        if row is None:
            row = {"ioc": ioc, "外联目标": ioc, "端口": "", "外联日期": ""}
        decision = decide_row(
            row,
            xmon_info,
            hash_map,
            wfy_info,
            wd_info,
            ai_info,
            external_info,
            atateam_evidence_summary,
            siyubo_evidence_summary,
            sc_malicious,
            state,
        )
        print_debug_ioc(ioc, xmon_info, hash_map, wfy_info, wd_info, sc_malicious, decision)
        decisions[ioc] = decision
    finish_stage("生成研判结果", stage_time)

    return PipelineResult(
        decisions=decisions,
        ai_map=ai_map,
        xmon_map=xmon_map,
        wfy_map=wfy_map,
        hash_map=hash_map,
        wd_map=wd_map,
        atateam_summary_map=atateam_summary_map,
        siyubo_summary_map=siyubo_summary_map,
        external_ioc_map=external_ioc_map,
        sc_malicious_map=sc_map,
        state=state,
    )
