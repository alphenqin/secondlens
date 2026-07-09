from __future__ import annotations

import argparse
from pathlib import Path

from app.config import load_config, with_runtime_overrides
from app.scheduler import Scheduler, print_run_result
from app.worker import Worker


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="secondlens bucket secondary judgment worker")
    parser.add_argument("--config", default="config.yaml", help="YAML config file path")
    parser.add_argument("--max-tasks", type=int, help="Limit tasks in this run")
    subparsers = parser.add_subparsers(dest="command")

    local_parser = subparsers.add_parser("local", help="Process downloaded inbox files under data/input")
    local_parser.add_argument("--source-dir", default="", help="Override local inbox directory")

    bucket_parser = subparsers.add_parser("bucket", help="Read tasks from inbox bucket and write local/upload results")
    bucket_parser.add_argument("--prefix", default="", help="Inbox object prefix, for example 20260707/")
    bucket_parser.add_argument("--upload", action="store_true", help="Upload result JSON to outbox bucket")

    watch_parser = subparsers.add_parser("watch", help="Keep polling the inbox bucket")
    watch_parser.add_argument("--prefix", default="", help="Inbox object prefix. Empty means scan all visible tasks.")
    watch_parser.add_argument("--interval", type=int, default=0, help="Polling interval seconds. Defaults to config value.")
    watch_parser.add_argument("--upload", action="store_true", help="Upload result JSON to outbox bucket")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    config = load_config(args.config)
    if args.max_tasks is not None:
        config = with_runtime_overrides(config, max_tasks=args.max_tasks)
    if getattr(args, "upload", False):
        config = with_runtime_overrides(config, upload=True)

    worker = Worker(config)
    command = args.command or "watch"

    if command == "local":
        source_dir = Path(args.source_dir) if args.source_dir else None
        processed = worker.run_local(source_dir)
    elif command == "watch":
        prefix = getattr(args, "prefix", "")
        interval = getattr(args, "interval", 0)
        Scheduler(config, worker=worker).watch(prefix=prefix, interval=interval or None)
        return
    else:
        processed = worker.run_bucket(prefix=args.prefix)

    print_run_result(processed)


if __name__ == "__main__":
    main()
