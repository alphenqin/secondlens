from __future__ import annotations

from app.config import AppConfig
from app.services import ProcessedTaskStore
from app.utils.logger import setup_logger
from app.worker import Worker


class Scheduler:
    def __init__(self, config: AppConfig, worker: Worker | None = None):
        self.config = config
        self.worker = worker or Worker(config)
        self.state_store = ProcessedTaskStore(config.runtime.state_file)
        self.logger = setup_logger()

    def watch(self, *, prefix: str = "", interval: int | None = None) -> None:
        sleep_seconds = interval or self.config.runtime.poll_interval_seconds
        try:
            from apscheduler.schedulers.blocking import BlockingScheduler
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Missing APScheduler. Install dependencies with: python3 -m pip install -r requirements.txt") from exc

        scheduler = BlockingScheduler(timezone="Asia/Shanghai")
        scheduler.add_job(
            self.run_once,
            "interval",
            seconds=sleep_seconds,
            kwargs={"prefix": prefix},
            id="scan_inbox_bucket",
            max_instances=1,
            coalesce=True,
            replace_existing=True,
        )
        self.logger.info(
            "watching inbox={} prefix={!r} interval={}s upload={}",
            self.config.storage.inbox_name,
            prefix,
            sleep_seconds,
            self.config.runtime.upload,
        )
        self.run_once(prefix=prefix)
        try:
            scheduler.start()
        except KeyboardInterrupt:
            self.logger.info("stopped")

    def run_once(self, *, prefix: str = "") -> None:
        try:
            processed = self.worker.run_bucket(prefix=prefix, state_store=self.state_store)
            log_run_result(processed, self.logger)
        except Exception:
            self.logger.exception("scheduled bucket scan failed")


def print_run_result(processed) -> None:
    print(f"processed={len(processed)}")
    for item in processed:
        upload_text = " uploaded" if item.uploaded else ""
        print(f"{item.task.id} {item.task.ioc} -> {item.local_path}{upload_text}")
        if item.validation_errors:
            print(f"  validation_errors={'; '.join(item.validation_errors)}")
        if item.overdue:
            print("  overdue=true")


def log_run_result(processed, logger) -> None:
    logger.info("processed={}", len(processed))
    for item in processed:
        logger.info(
            "task_id={} ioc={} output={} uploaded={} overdue={} validation_errors={}",
            item.task.id,
            item.task.ioc,
            item.local_path,
            item.uploaded,
            item.overdue,
            list(item.validation_errors),
        )
