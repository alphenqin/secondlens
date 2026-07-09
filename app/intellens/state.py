"""IntelLens 流水线运行期可变状态：失败追踪列表、线程锁、线程局部 Session、快照缓存。

并发安全模型：失败追踪列表已改为 **request-scoped**——每次流水线运行各自创建一个
``PipelineState`` 实例，互不污染。线程池里的 worker 通过闭包捕获本次请求的 ``state``，
天然拿到正确的那份。``WD_SNAPSHOT_TOPIC_SUMMARY_CACHE`` 是跨请求复用的 LLM 缓存（命中省
一次大模型调用，结果确定性相同），保留为模块全局；``THREAD_LOCAL`` 是线程级 Session 连接池，
同样保留为模块全局。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import Lock, local


# 跨请求复用的 LLM 快照主题缓存（dict get/set 在 GIL 下原子，并发安全）。
WD_SNAPSHOT_TOPIC_SUMMARY_CACHE: dict[str, str] = {}
# 线程级 requests.Session 连接池，跨请求复用线程时复用连接，是性能特性。
THREAD_LOCAL = local()


@dataclass
class PipelineState:
    """单次流水线运行（一次请求/一次批处理）的私有失败账本。

    每个字段都是本次运行独立拥有的，不与其他并发请求共享。``run_decision_pipeline``
    在入口创建一个实例，顺着参数传给所有写/读失败的函数；线程池 worker 通过闭包捕获。
    """

    xmon_failed_iocs: list[str] = field(default_factory=list)
    tagmon_failed_iocs: list[str] = field(default_factory=list)
    tagmon_failed_lock: Lock = field(default_factory=Lock)
    hash_failed_queries: list[str] = field(default_factory=list)
    hash_failed_lock: Lock = field(default_factory=Lock)
    wfy_failed_queries: list[str] = field(default_factory=list)
    external_ioc_failed_queries: list[str] = field(default_factory=list)
    sc_failed_iocs: list[str] = field(default_factory=list)
    wd_failed_iocs: list[str] = field(default_factory=list)
    ai_failed_iocs: list[str] = field(default_factory=list)
    wd_llm_failed_iocs: list[str] = field(default_factory=list)
    atateam_llm_failed_iocs: list[str] = field(default_factory=list)
    atateam_llm_rejected_summaries: list[str] = field(default_factory=list)
    siyubo_llm_failed_iocs: list[str] = field(default_factory=list)
    siyubo_llm_rejected_summaries: list[str] = field(default_factory=list)
    ai_llm_rejected_summaries: list[str] = field(default_factory=list)

