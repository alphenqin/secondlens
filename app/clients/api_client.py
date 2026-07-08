from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterator

from app.config import StorageConfig


def parse_aksk_file(path: Path) -> dict[str, str]:
    access_key = os.getenv("QH360_ACCESS_KEY") or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("QH360_SECRET_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")

    if path.exists():
        values = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for index, line in enumerate(values):
            if re.search(r"ACCESS[_ ]?KEY|ACCESS_KEY|AK", line, re.I):
                access_key = access_key or line.partition(":")[2].strip() or line.partition("：")[2].strip()
                if not access_key and index + 1 < len(values):
                    access_key = values[index + 1]
            if re.search(r"SECRET[_ ]?KEY|SECRET_KEY|SK", line, re.I):
                secret_key = secret_key or line.partition(":")[2].strip() or line.partition("：")[2].strip()
                if not secret_key and index + 1 < len(values):
                    secret_key = values[index + 1]
        if not access_key and values:
            access_key = values[0]
        if not secret_key and len(values) > 1:
            secret_key = values[1]

    if not access_key or not secret_key:
        raise RuntimeError("Missing AK/SK. Set QH360_ACCESS_KEY/QH360_SECRET_KEY or configure aksk_file.")
    return {"access_key": access_key, "secret_key": secret_key}


class ObjectStorage:
    def __init__(self, config: StorageConfig):
        self.config = config
        self.client = self._make_client()

    def _make_client(self):
        try:
            import pip_system_certs.wrapt_requests  # type: ignore  # noqa: F401
        except ImportError:
            pass
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Missing boto3. Install project requirements first.") from exc

        credentials = parse_aksk_file(self.config.aksk_file)
        if not self.config.verify_tls:
            verify: bool | str = False
        elif self.config.ca_file and self.config.ca_file.exists():
            verify = str(self.config.ca_file)
        else:
            verify = True

        return boto3.client(
            "s3",
            endpoint_url=self.config.endpoint,
            aws_access_key_id=credentials["access_key"],
            aws_secret_access_key=credentials["secret_key"],
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
            verify=verify,
        )

    def iter_objects(self, bucket: str, prefix: str = "") -> Iterator[dict[str, Any]]:
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            yield from page.get("Contents", [])

    def read_json(self, bucket: str, key: str) -> dict[str, Any]:
        response = self.client.get_object(Bucket=bucket, Key=key)
        return json.loads(response["Body"].read().decode("utf-8"))

    def upload_json(self, bucket: str, key: str, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.client.put_object(Bucket=bucket, Key=key, Body=body, ContentType="application/json; charset=utf-8")
