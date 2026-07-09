from app.models import JudgmentTask
from app.services.intellens_service import IntelLensJudgment
from app.services.task_service import TaskService, clean_report_url, is_valid_report_url
from app.services.wfy_status_service import WfyStatusService
from datetime import datetime, timedelta, timezone


class FakeIntellensService:
    def judge_one(self, ioc):
        return IntelLensJudgment(
            ops="+",
            evidence={
                "sample_behavior": {"hash_md5": "5d41402abc4b2a76b9719d911017c592"},
                "source_links": "https://threatintel.com/report/123",
                "related_vulnerabilities": ["CVE-2026-1234"],
                "traffic_fragments": {
                    "traffic_type": "tls",
                    "traffic_pattern": "tls.sni: evil.example",
                    "description": "TLS SNI特征",
                },
                "phishing_details": None,
                "other_evidence": "{\"ip\":\"evil.example\"}",
            },
        )


def make_service():
    return TaskService(intellens_service=FakeIntellensService())


def test_build_result_payload_is_valid_for_basic_task():
    service = make_service()
    task = JudgmentTask(id="123456", ioc="https://evil.example/a", date="20260707")

    judgment = service.judge(task)
    payload = service.build_result_payload(task, judgment)

    assert service.validate_result_payload(payload) == []
    assert payload["evidence"]["sample_behavior"]["hash_md5"] == "5d41402abc4b2a76b9719d911017c592"
    assert payload["evidence"]["source_links"] == "https://threatintel.com/report/123"
    assert payload["evidence"]["related_vulnerabilities"] == ["CVE-2026-1234"]
    assert payload["evidence"]["traffic_fragments"]["traffic_type"] == "tls"
    assert payload["evidence"]["phishing_details"] is None


def test_validate_result_payload_rejects_unknown_ioc():
    service = make_service()
    task = JudgmentTask(id="123456", ioc="not a valid ioc", date="20260707")

    payload = service.build_result_payload(task, service.judge(task))

    assert "ioc_type must be ip/domain/url" in service.validate_result_payload(payload)


def test_validate_result_payload_rejects_invalid_category():
    service = make_service()
    task = JudgmentTask(id="123456", ioc="evil.example", date="20260707")
    payload = service.build_result_payload(task, service.judge(task))

    payload["category_new"] = 999999

    assert "category_new enum invalid" in service.validate_result_payload(payload)


def test_is_overdue_uses_received_at():
    service = make_service()
    task = JudgmentTask(
        id="123456",
        ioc="evil.example",
        date="20260707",
        received_at=datetime.now(timezone.utc) - timedelta(seconds=3601),
    )

    assert service.is_overdue(task, 3600)


def test_source_links_must_be_valid_url():
    service = make_service()
    task = JudgmentTask(id="123456", ioc="evil.example", date="20260707")
    payload = service.build_result_payload(task, service.judge(task))
    payload["evidence"] = {"source_links": "not-url"}

    assert "source_links must contain valid http/https URL" in service.validate_result_payload(payload)


def test_clean_report_url_removes_suffix():
    assert clean_report_url("https://example.com/a#frag") == "https://example.com/a"
    assert is_valid_report_url("https://example.com/a")


def test_traffic_fragment_requires_core_fields():
    service = make_service()
    task = JudgmentTask(id="123456", ioc="evil.example", date="20260707")
    payload = service.build_result_payload(task, service.judge(task))
    payload["evidence"] = {"traffic_fragments": {"traffic_type": "http"}}

    errors = service.validate_result_payload(payload)

    assert "traffic_fragments.traffic_pattern is required" in errors
    assert "traffic_fragments.description is required" in errors


def test_wfy_status_maps_to_rd_status():
    service = WfyStatusService()

    assert service.status_from_wfy_info({"status": "ACTIVE"}) == "active"
    assert service.status_from_wfy_info({"status": "OVER"}) == "inactive"
    assert service.status_from_wfy_info({"status": "SINKHOLE"}) == "sinkhole"
    assert service.status_from_wfy_info({"status": "UNKNOWN"}) == "unknown"
