from app.models import JudgmentTask
from app.services.task_service import TaskService, clean_report_url, is_valid_report_url
from datetime import datetime, timedelta, timezone


def test_build_result_payload_is_valid_for_basic_task():
    service = TaskService()
    task = JudgmentTask(id="123456", ioc="https://evil.example/a", date="20260707")

    judgment = service.judge(task)
    payload = service.build_result_payload(task, judgment)

    assert service.validate_result_payload(payload) == []


def test_validate_result_payload_rejects_unknown_ioc():
    service = TaskService()
    task = JudgmentTask(id="123456", ioc="not a valid ioc", date="20260707")

    payload = service.build_result_payload(task, service.judge(task))

    assert "ioc_type must be ip/domain/url" in service.validate_result_payload(payload)


def test_validate_result_payload_rejects_invalid_category():
    service = TaskService()
    task = JudgmentTask(id="123456", ioc="evil.example", date="20260707")
    payload = service.build_result_payload(task, service.judge(task))

    payload["category_new"] = 999999

    assert "category_new enum invalid" in service.validate_result_payload(payload)


def test_is_overdue_uses_received_at():
    service = TaskService()
    task = JudgmentTask(
        id="123456",
        ioc="evil.example",
        date="20260707",
        received_at=datetime.now(timezone.utc) - timedelta(seconds=3601),
    )

    assert service.is_overdue(task, 3600)


def test_source_links_must_be_valid_url():
    service = TaskService()
    task = JudgmentTask(id="123456", ioc="evil.example", date="20260707")
    payload = service.build_result_payload(task, service.judge(task))
    payload["evidence"] = {"source_links": "not-url"}

    assert "source_links must contain valid http/https URL" in service.validate_result_payload(payload)


def test_clean_report_url_removes_suffix():
    assert clean_report_url("https://example.com/a#frag") == "https://example.com/a"
    assert is_valid_report_url("https://example.com/a")


def test_traffic_fragment_requires_core_fields():
    service = TaskService()
    task = JudgmentTask(id="123456", ioc="evil.example", date="20260707")
    payload = service.build_result_payload(task, service.judge(task))
    payload["evidence"] = {"traffic_fragments": {"traffic_type": "http"}}

    errors = service.validate_result_payload(payload)

    assert "traffic_fragments.traffic_pattern is required" in errors
    assert "traffic_fragments.description is required" in errors
