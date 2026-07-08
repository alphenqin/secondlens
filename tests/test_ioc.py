from app.services.task_service import parse_ioc


def test_parse_url():
    parsed = parse_ioc("https://example.com/a")
    assert parsed.ioc_type == "url"
    assert parsed.host == "example.com"
    assert parsed.port == 443
    assert parsed.uri == "/a"


def test_parse_ip_port():
    parsed = parse_ioc("1.2.3.4:8080")
    assert parsed.ioc_type == "ip"
    assert parsed.host == "1.2.3.4"
    assert parsed.port == 8080
