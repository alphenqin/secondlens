from __future__ import annotations


MALICIOUS_STAMPS = {"black", "white", "gray", "suspicious"}
STATUSES = {"active", "inactive", "sinkhole", "unknown"}

# 附件二“情报来源”定义 vendor。RD 正文也出现 authority，这里作为兼容别名允许。
BASES = {"public", "vendor", "authority", "device", "honeypot", "sample", "partner"}
GENERATION_METHODS = {"direct", "machine", "analyst", "pivot"}

CATEGORY_V8_CODES = {
    100,
    200,
    300,
    301,
    302,
    400,
    500,
    600,
    700,
    800,
    900,
    1000,
    1100,
    1101,
    1102,
    1200,
    1300,
    1400,
    9900,
}

CATEGORY_V9_CODES = {
    10100,
    10200,
    10300,
    10400,
    10500,
    10600,
    10700,
    9900,
}

CATEGORY_NEW_CODES = {
    100000,
    100001,
    100002,
    100003,
    100004,
    100005,
    100006,
    100007,
    100008,
    100009,
    100010,
    100011,
    100012,
    100013,
    100014,
    100015,
    100016,
    100017,
}

PHISHING_CATEGORY_CODES = {100005, 100006}
