from app.models import JudgmentTask
from app.services.intellens_service import IntelLensJudgment
from app.services.task_service import TaskService, clean_report_url, is_valid_report_url, ops_from_wfy_judge
from app.services.wfy_service import WfyService
from datetime import datetime, timedelta, timezone


class FakeIntellensService:
    def judge_one(self, ioc):
        return IntelLensJudgment(
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


class FakeWfyService:
    def result_fields_for_ioc(self, ioc):
        return {
            "judge": "black",
            "base": "sample",
            "tpd": False,
            "status": "active",
            "confidence": 3,
            "risk_level": 3,
            "first_seen": "2026-06-02T01:50:52.000Z",
            "category_v8": 301,
            "category_v9": 10300,
            "category_new": 100008,
            "control_type": "c2",
            "file_hash": ["5d41402abc4b2a76b9719d911017c592"],
            "last_seen": "2026-06-03T01:50:52.000Z",
            "created_time": "2026-06-02T01:50:52.000Z",
            "modified_time": "2026-06-04T01:50:52.000Z",
            "campaign": "Silver fox",
            "malicious_family": ["Silver fox"],
            "platform": ["windows"],
            "tags": ["Silver fox", "c2"],
            "ttps": ["T1059.001"],
            "scene": 200001,
            "whois": {"domainname": ["evil.example"]},
            "icp": None,
            "dns": ["192.238.134.233"],
            "open_port": [80, 443],
            "geo": ["美国"],
            "dynamic_domain": False,
            "certificate": None,
        }


def make_service():
    return TaskService(intellens_service=FakeIntellensService(), wfy_service=FakeWfyService())


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
    service = WfyService()

    assert service.status_from_wfy_info({"status": "ACTIVE"}) == "active"
    assert service.status_from_wfy_info({"status": "OVER"}) == "inactive"
    assert service.status_from_wfy_info({"status": "SINKHOLE"}) == "sinkhole"
    assert service.status_from_wfy_info({"status": "UNKNOWN"}) == "unknown"


def test_wfy_v2_fields_backfill_payload():
    service = make_service()
    task = JudgmentTask(id="123456", ioc="192.238.134.233:443", date="20260707")

    payload = service.build_result_payload(task, service.judge(task))

    assert payload["ops"] == "+"
    assert payload["malicious_stamp"] == ""
    assert payload["generation_method"] == ""
    assert payload["base"] == "sample"
    assert payload["tpd"] is False
    assert payload["status"] == "active"
    assert payload["confidence"] == 3
    assert payload["risk_level"] == 3
    assert payload["first_seen"] == "2026-06-02T01:50:52.000Z"
    assert payload["category_v8"] == 301
    assert payload["category_v9"] == 10300
    assert payload["category_new"] == 100008
    assert payload["control_type"] == ""
    assert payload["file_hash"] == []
    assert payload["last_seen"] == ""
    assert payload["created_time"] is None
    assert payload["modified_time"] is None
    assert payload["campaign"] is None
    assert payload["malicious_family"] == []
    assert payload["platform"] == []
    assert payload["tags"] == []
    assert payload["ttps"] == []
    assert payload["scene"] == 200001
    assert payload["whois"] == {"domainname": ["evil.example"]}
    assert payload["icp"] is None
    assert payload["dns"] == ["192.238.134.233"]
    assert payload["open_port"] == [80, 443]
    assert payload["geo"] == ["美国"]
    assert payload["dynamic_domain"] is False
    assert payload["certificate"] is None


def test_ops_uses_wfy_black_only_as_non_false_positive():
    assert ops_from_wfy_judge("black") == "+"
    assert ops_from_wfy_judge("BLACK") == "+"
    assert ops_from_wfy_judge("white") == "-"
    assert ops_from_wfy_judge("gray") == "-"
    assert ops_from_wfy_judge("suspicious") == "-"
    assert ops_from_wfy_judge("") == "-"


def test_false_positive_payload_keeps_full_optional_shape():
    class GrayWfyService(FakeWfyService):
        def result_fields_for_ioc(self, ioc):
            fields = super().result_fields_for_ioc(ioc)
            fields.update(
                {
                    "judge": "gray",
                    "whois": None,
                    "icp": None,
                    "dns": None,
                    "open_port": [80, 443, 4444],
                    "certificate": None,
                }
            )
            return fields

    service = TaskService(intellens_service=FakeIntellensService(), wfy_service=GrayWfyService())
    task = JudgmentTask(id="123456", ioc="185.130.5.253:4444", date="20260707")

    payload = service.build_result_payload(task, service.judge(task))

    assert payload["ops"] == "-"
    assert payload["ioc_host"] == "185.130.5.253"
    assert payload["ioc_port"] == 4444
    assert payload["ioc_uri"] is None
    assert payload["protocol"] is None
    assert payload["whois"] is None
    assert payload["icp"] is None
    assert payload["dns"] is None
    assert payload["open_port"] == [80, 443, 4444]
    assert payload["certificate"] is None
