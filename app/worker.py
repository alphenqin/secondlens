from __future__ import annotations

import json
import re
from pathlib import Path

from app.clients import ObjectStorage
from app.config import AppConfig
from app.models import AlertMessage, JudgmentTask, ProcessedTask
from app.services import ProcessedTaskStore, TaskService


TASK_FILE_RE = re.compile(r"(?P<date>\d{8})/(?P<task_id>\d+)/secon_analysis_(?P=task_id)\.json$")
ALERT_FILE_RE = re.compile(r"(?P<date>\d{8})/(?P<task_id>\d+)/alert_message/alert_message_(?P=task_id)_\d+\.json$")


class Worker:
    def __init__(self, config: AppConfig, task_service: TaskService | None = None):
        self.config = config
        self.task_service = task_service or TaskService()

    def run_local(self, source_dir: Path | None = None) -> list[ProcessedTask]:
        source = source_dir or self.config.runtime.input_dir
        tasks = self._load_local_tasks(source)
        return self._process_tasks(tasks, storage=None)

    def run_bucket(self, prefix: str = "", state_store: ProcessedTaskStore | None = None) -> list[ProcessedTask]:
        storage = ObjectStorage(self.config.storage)
        tasks = self._load_bucket_tasks(storage, prefix=prefix)
        return self._process_tasks(tasks, storage=storage, state_store=state_store)

    def _process_tasks(
        self,
        tasks: list[JudgmentTask],
        storage: ObjectStorage | None,
        state_store: ProcessedTaskStore | None = None,
    ) -> list[ProcessedTask]:
        if state_store is not None:
            tasks = [task for task in tasks if not state_store.contains(task.source_key)]
        if self.config.runtime.max_tasks > 0:
            tasks = tasks[: self.config.runtime.max_tasks]

        processed: list[ProcessedTask] = []
        for task in tasks:
            judgment = self.task_service.judge(task)
            payload = self.task_service.build_result_payload(task, judgment)
            validation_errors = tuple(self.task_service.validate_result_payload(payload))
            overdue = self.task_service.is_overdue(task, self.config.runtime.task_deadline_seconds)
            key = self.task_service.result_key(task)
            local_path = self.config.runtime.output_dir / key
            if local_path.exists() and not self.config.runtime.overwrite_local:
                continue
            self.task_service.write_result(local_path, payload)
            uploaded = False
            if storage is not None and self.config.runtime.upload and not validation_errors:
                storage.upload_json(self.config.storage.outbox_name, key, payload)
                uploaded = True
            if state_store is not None:
                state_store.add(task.source_key)
            processed.append(
                ProcessedTask(
                    task=task,
                    key=key,
                    local_path=local_path,
                    uploaded=uploaded,
                    validation_errors=validation_errors,
                    overdue=overdue,
                )
            )
        return processed

    def _load_local_tasks(self, source: Path) -> list[JudgmentTask]:
        task_paths = sorted(source.glob("*/*/secon_analysis_*.json"))
        alerts_by_task = self._load_local_alerts(source)
        tasks: list[JudgmentTask] = []
        for path in task_paths:
            rel = path.relative_to(source).as_posix()
            match = TASK_FILE_RE.match(rel)
            if not match:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            task_id = match.group("task_id")
            alerts = tuple(alerts_by_task.get(task_id, []))
            tasks.append(JudgmentTask.from_dict(data, date=match.group("date"), source_key=rel, alerts=alerts))
        return tasks

    def _load_local_alerts(self, source: Path) -> dict[str, list[AlertMessage]]:
        alerts: dict[str, list[AlertMessage]] = {}
        for path in sorted(source.glob("*/*/alert_message/alert_message_*.json")):
            rel = path.relative_to(source).as_posix()
            match = ALERT_FILE_RE.match(rel)
            if not match:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            alerts.setdefault(match.group("task_id"), []).append(AlertMessage.from_dict(data))
        return alerts

    def _load_bucket_tasks(self, storage: ObjectStorage, prefix: str = "") -> list[JudgmentTask]:
        bucket = self.config.storage.inbox_name
        task_keys: list[str] = []
        modified_by_key = {}
        alert_keys_by_task: dict[str, list[str]] = {}
        for obj in storage.iter_objects(bucket, prefix):
            key = obj["Key"]
            task_match = TASK_FILE_RE.match(key)
            if task_match:
                task_keys.append(key)
                modified_by_key[key] = obj.get("LastModified")
                continue
            alert_match = ALERT_FILE_RE.match(key)
            if alert_match:
                alert_keys_by_task.setdefault(alert_match.group("task_id"), []).append(key)

        tasks: list[JudgmentTask] = []
        for key in sorted(task_keys):
            match = TASK_FILE_RE.match(key)
            if not match:
                continue
            task_id = match.group("task_id")
            alerts = tuple(AlertMessage.from_dict(storage.read_json(bucket, alert_key)) for alert_key in sorted(alert_keys_by_task.get(task_id, [])))
            tasks.append(
                JudgmentTask.from_dict(
                    storage.read_json(bucket, key),
                    date=match.group("date"),
                    source_key=key,
                    alerts=alerts,
                    received_at=modified_by_key.get(key),
                )
            )
        return tasks
