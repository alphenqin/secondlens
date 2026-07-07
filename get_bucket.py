#!/usr/bin/env python3
try:
    import pip_system_certs.wrapt_requests  # type: ignore  # noqa: F401
except ImportError:
    pass

import argparse
import os
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional


DEFAULT_ENDPOINT = "https://oss.wfy.gov110.cn"
DEFAULT_AKSK_FILE = "360-aksk.txt"
DEFAULT_CA_FILE = "wfy-root-ca.pem"
DEFAULT_SUPPLIER_CODE = "360"
DEFAULT_BUCKET_KIND = "inbox"
DEFAULT_ENV = "dev"


def parse_aksk_file(path: Path) -> Dict[str, str]:
    access_key = os.getenv("QH360_ACCESS_KEY") or os.getenv("AWS_ACCESS_KEY_ID")
    secret_key = os.getenv("QH360_SECRET_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")

    if path.exists():
        text = path.read_text(encoding="utf-8")
        values = [line.strip() for line in text.splitlines() if line.strip()]

        for i, line in enumerate(values):
            if re.search(r"ACCESS[_ ]?KEY|ACCESS_KEY|AK", line, re.I):
                access_key = access_key or line.partition("：")[2].strip() or line.partition(":")[2].strip()
                if not access_key and i + 1 < len(values):
                    access_key = values[i + 1]
            if re.search(r"SECRET[_ ]?KEY|SECRET_KEY|SK", line, re.I):
                secret_key = secret_key or line.partition("：")[2].strip() or line.partition(":")[2].strip()
                if not secret_key and i + 1 < len(values):
                    secret_key = values[i + 1]

        if not access_key and values:
            access_key = values[0]
        if not secret_key and len(values) > 1:
            secret_key = values[1]

    if not access_key or not secret_key:
        raise SystemExit(
            "缺少 AK/SK。请设置 QH360_ACCESS_KEY/QH360_SECRET_KEY，或提供 --aksk-file。"
        )

    return {"access_key": access_key, "secret_key": secret_key}


def make_client(endpoint: str, access_key: str, secret_key: str, verify):
    try:
        import boto3
        from botocore.exceptions import ClientError, EndpointConnectionError, SSLError
        from botocore.config import Config
    except ImportError as exc:
        raise SystemExit("缺少依赖 boto3。请先执行: python3 -m pip install -r requirements.txt") from exc

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
        ),
        verify=verify,
    )
    client._bucket_script_client_error = ClientError
    client._bucket_script_ssl_error = SSLError
    client._bucket_script_endpoint_error = EndpointConnectionError
    return client


def build_bucket_name(kind: str, supplier_code: str, env: str) -> str:
    bucket = f"second-analysis-{kind}-{supplier_code}"
    if env == "dev":
        bucket += "-dev"
    return bucket


def iter_objects(s3_client, bucket: str, prefix: str = "") -> Iterator[dict]:
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        yield from page.get("Contents", [])


def iter_object_pages(s3_client, bucket: str, prefix: str = "") -> Iterator[dict]:
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        yield page


def iter_directory_page(
    s3_client, bucket: str, prefix: str = "", delimiter: str = "/"
) -> Iterator[dict]:
    paginator = s3_client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix, Delimiter=delimiter):
        for item in page.get("CommonPrefixes", []):
            yield {"type": "dir", "key": item["Prefix"]}
        for item in page.get("Contents", []):
            if item["Key"] != prefix:
                yield {"type": "file", **item}


def iter_recursive_listing(s3_client, bucket: str, prefix: str = "") -> Iterator[dict]:
    directories = set()
    files = []

    for obj in iter_objects(s3_client, bucket, prefix):
        key = obj["Key"]
        if key == prefix:
            continue

        parts = key.split("/")
        for index in range(1, len(parts)):
            directory = "/".join(parts[:index]) + "/"
            if directory.startswith(prefix):
                directories.add(directory)

        if not key.endswith("/"):
            files.append(obj)

    for directory in sorted(directories):
        yield {"type": "dir", "key": directory}
    for obj in sorted(files, key=lambda item: item["Key"]):
        yield {"type": "file", **obj}


def safe_local_path(download_dir: Path, key: str) -> Path:
    parts = [part for part in key.split("/") if part not in ("", ".", "..")]
    if not parts:
        raise ValueError(f"非法对象 Key: {key!r}")
    return download_dir.joinpath(*parts)


def print_listing(items: Iterable[dict]) -> None:
    count = 0
    for item in items:
        count += 1
        if item["type"] == "dir":
            print(f"[DIR]  {item['key']}")
        else:
            modified = item["LastModified"].astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
            print(f"[FILE] {item['Key']}\t{item['Size']} bytes\t{modified}")
    if count == 0:
        print("未找到文件或目录。可用 `scan` 命令扫描所有可见桶，或检查 --prefix。")


def download_objects(s3_client, bucket: str, prefix: str, download_dir: Path) -> None:
    download_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    total_size = 0

    for obj in iter_objects(s3_client, bucket, prefix):
        key = obj["Key"]
        if key.endswith("/"):
            continue

        local_path = safe_local_path(download_dir, key)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        print(f"下载: {key} -> {local_path}")
        s3_client.download_file(bucket, key, str(local_path))
        count += 1
        total_size += obj.get("Size", 0)

    print(f"完成: 下载 {count} 个文件，共 {total_size} bytes，保存到 {download_dir}")


def download_single_object(s3_client, bucket: str, key: str, size: int, download_dir: Path) -> None:
    local_path = safe_local_path(download_dir, key)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"下载: {key} -> {local_path}")
    s3_client.download_file(bucket, key, str(local_path))
    print(f"完成: 下载 1 个文件，共 {size} bytes，保存到 {local_path}")


def get_object_size_if_exists(s3_client, bucket: str, key: str) -> Optional[int]:
    try:
        response = s3_client.head_object(Bucket=bucket, Key=key)
    except getattr(s3_client, "_bucket_script_client_error") as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        status_code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if error_code in ("404", "NoSuchKey", "NotFound") or status_code == 404:
            return None
        raise
    return int(response.get("ContentLength", 0))


def download_path(s3_client, bucket: str, path: str, download_dir: Path) -> None:
    key = path.lstrip("/")
    if not key:
        download_objects(s3_client, bucket, "", download_dir)
        return

    size = get_object_size_if_exists(s3_client, bucket, key)
    if size is not None:
        download_single_object(s3_client, bucket, key, size, download_dir)
        return

    directory_prefix = key if key.endswith("/") else f"{key}/"
    download_objects(s3_client, bucket, directory_prefix, download_dir)


def list_buckets(s3_client) -> None:
    response = s3_client.list_buckets()
    buckets = response.get("Buckets", [])
    if not buckets:
        print("当前 AK/SK 未列出任何桶，可能没有 ListBuckets 权限。")
        return

    for bucket in buckets:
        created = bucket.get("CreationDate")
        created_text = created.astimezone().strftime("%Y-%m-%d %H:%M:%S %z") if created else "-"
        print(f"{bucket['Name']}\t{created_text}")


def scan_buckets(s3_client, prefix: str, sample_limit: int) -> None:
    response = s3_client.list_buckets()
    buckets = response.get("Buckets", [])
    if not buckets:
        print("当前 AK/SK 未列出任何桶，可能没有 ListBuckets 权限。")
        return

    for bucket_item in buckets:
        bucket = bucket_item["Name"]
        count = 0
        total_size = 0
        latest = None
        samples = []
        failed = None

        try:
            for page in iter_object_pages(s3_client, bucket, prefix):
                for obj in page.get("Contents", []):
                    count += 1
                    total_size += obj.get("Size", 0)
                    if latest is None or obj["LastModified"] > latest["LastModified"]:
                        latest = obj
                    if len(samples) < sample_limit:
                        samples.append(obj)
        except Exception as exc:
            failed = exc

        if failed:
            print(f"[ERROR] {bucket}: {failed}")
            continue

        latest_text = "-"
        if latest:
            latest_time = latest["LastModified"].astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
            latest_text = f"{latest['Key']} ({latest_time})"

        print(f"[BUCKET] {bucket}\t对象数={count}\t总大小={total_size} bytes\t最新={latest_text}")
        for obj in samples:
            modified = obj["LastModified"].astimezone().strftime("%Y-%m-%d %H:%M:%S %z")
            print(f"  [FILE] {obj['Key']}\t{obj['Size']} bytes\t{modified}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="列出 S3 兼容对象存储桶中的目录/文件，并可按前缀下载文件。"
    )
    parser.add_argument(
        "--bucket",
        default=os.getenv("BUCKET_NAME"),
        help="桶名称；不传时按 --bucket-kind/--supplier-code/--env 自动生成",
    )
    parser.add_argument(
        "--bucket-kind",
        choices=("inbox", "outbox"),
        default=DEFAULT_BUCKET_KIND,
        help="桶类型，inbox=只读桶，outbox=只写桶，默认 inbox",
    )
    parser.add_argument(
        "--supplier-code",
        default=DEFAULT_SUPPLIER_CODE,
        help=f"供应商编码，默认 {DEFAULT_SUPPLIER_CODE}",
    )
    parser.add_argument(
        "--env",
        choices=("prod", "dev"),
        default=DEFAULT_ENV,
        help=f"桶环境，prod=正式桶，dev=测试桶，默认 {DEFAULT_ENV}",
    )
    parser.add_argument("--prefix", default="", help="目录或对象前缀，例如 data/2026/")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="对象存储 Endpoint")
    parser.add_argument("--aksk-file", default=DEFAULT_AKSK_FILE, help="AK/SK 文件路径")
    parser.add_argument(
        "--download-dir",
        default="download",
        help="下载保存目录，默认 download",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="关闭 HTTPS 证书校验。仅在本机 CA 未安装且明确接受风险时使用。",
    )
    parser.add_argument(
        "--ca-file",
        default=os.getenv("SSL_CERT_FILE")
        or os.getenv("REQUESTS_CA_BUNDLE")
        or (DEFAULT_CA_FILE if Path(DEFAULT_CA_FILE).exists() else None),
        help="指定 CA 证书文件路径，例如 /path/to/ca.pem",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=5,
        help="scan 命令中每个桶最多展示的样例文件数，默认 5",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    list_parser = subparsers.add_parser("list", help="列出指定桶内所有目录和文件")
    list_parser.add_argument("bucket_name", nargs="?", help="桶名，例如 second-analysis-inbox-360-dev")

    download_parser = subparsers.add_parser(
        "download",
        help="下载指定路径；精确到文件名时下载单文件，指定目录时下载整个目录",
    )
    download_parser.add_argument(
        "path",
        help="桶内路径，例如 data/a.txt 或 data/",
    )

    subparsers.add_parser("buckets", help="列出当前 AK/SK 可见的桶")
    subparsers.add_parser("scan", help="扫描所有可见桶，统计对象数量并展示样例文件")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    positional_bucket = getattr(args, "bucket_name", None)
    bucket = positional_bucket or args.bucket or build_bucket_name(args.bucket_kind, args.supplier_code, args.env)
    credentials = parse_aksk_file(Path(args.aksk_file))
    s3_client = make_client(
        endpoint=args.endpoint,
        access_key=credentials["access_key"],
        secret_key=credentials["secret_key"],
        verify=False if args.no_verify else (args.ca_file or True),
    )

    try:
        if args.command == "list":
            print_listing(iter_recursive_listing(s3_client, bucket, args.prefix))
        elif args.command == "download":
            download_path(s3_client, bucket, args.path, Path(args.download_dir))
        elif args.command == "buckets":
            list_buckets(s3_client)
        elif args.command == "scan":
            scan_buckets(s3_client, args.prefix, args.sample_limit)
    except getattr(s3_client, "_bucket_script_client_error") as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchBucket":
            candidates = [
                build_bucket_name("inbox", args.supplier_code, "prod"),
                build_bucket_name("inbox", args.supplier_code, "dev"),
                build_bucket_name("outbox", args.supplier_code, "prod"),
                build_bucket_name("outbox", args.supplier_code, "dev"),
            ]
            raise SystemExit(
                f"桶不存在: {bucket}。请确认使用正式桶还是测试桶；可尝试 "
                f"`--env dev`，或显式指定 `--bucket`。候选桶名: {', '.join(candidates)}"
            ) from exc
        raise
    except getattr(s3_client, "_bucket_script_ssl_error") as exc:
        raise SystemExit(
            "SSL 证书校验失败。请先执行 `python3 -m pip install -r requirements.txt` "
            "并按供应商要求安装 CA 证书；如果已有 CA 文件可追加 `--ca-file /path/to/ca.pem`，"
            "临时验证连通性可追加 `--no-verify`。"
        ) from exc
    except getattr(s3_client, "_bucket_script_endpoint_error") as exc:
        raise SystemExit(
            f"无法连接 Endpoint: {args.endpoint}。请确认当前网络能解析并访问该域名，"
            "必要时先连接内网/VPN，或检查 DNS 配置。"
        ) from exc


if __name__ == "__main__":
    main()
