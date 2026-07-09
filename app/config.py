from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class StorageConfig:
    endpoint: str = "https://oss.wfy.gov110.cn"
    supplier_code: str = "360"
    env: str = "dev"
    inbox_bucket: str | None = None
    outbox_bucket: str | None = None
    aksk_file: Path = PROJECT_ROOT / "secret" / "360-aksk.txt"
    ca_file: Path | None = PROJECT_ROOT / "secret" / "wfy-root-ca.pem"
    verify_tls: bool = True

    @property
    def inbox_name(self) -> str:
        return self.inbox_bucket or build_bucket_name("inbox", self.supplier_code, self.env)

    @property
    def outbox_name(self) -> str:
        return self.outbox_bucket or build_bucket_name("outbox", self.supplier_code, self.env)


@dataclass(frozen=True)
class RuntimeConfig:
    data_dir: Path = PROJECT_ROOT / "data"
    max_tasks: int = 0
    poll_interval_seconds: int = 60
    task_deadline_seconds: int = 3600
    upload: bool = False
    overwrite_local: bool = False

    @property
    def input_dir(self) -> Path:
        return self.data_dir / "input"

    @property
    def output_dir(self) -> Path:
        return self.data_dir / "output"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def state_file(self) -> Path:
        return self.work_dir / "processed_tasks.json"


@dataclass(frozen=True)
class AppConfig:
    storage: StorageConfig
    runtime: RuntimeConfig


def build_bucket_name(kind: str, supplier_code: str, env: str) -> str:
    bucket = f"second-analysis-{kind}-{supplier_code}"
    if env == "dev":
        bucket += "-dev"
    return bucket


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if yaml is None:
        raise RuntimeError("pyyaml is required to load YAML config files")
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}
    if not isinstance(data, dict):
        raise RuntimeError(f"Config file must contain a mapping: {path}")
    return data


def _as_path(value: Any, default: Path | None = None) -> Path | None:
    if value in (None, ""):
        return default
    path = Path(str(value)).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = Path(path) if path else PROJECT_ROOT / "config.yaml"
    raw = _read_yaml(config_path)
    storage_raw = raw.get("storage", {}) if isinstance(raw.get("storage", {}), dict) else {}
    runtime_raw = raw.get("runtime", {}) if isinstance(raw.get("runtime", {}), dict) else {}

    storage = StorageConfig(
        endpoint=str(storage_raw.get("endpoint") or StorageConfig.endpoint),
        supplier_code=str(storage_raw.get("supplier_code") or "360"),
        env=str(storage_raw.get("env") or "dev"),
        inbox_bucket=storage_raw.get("inbox_bucket"),
        outbox_bucket=storage_raw.get("outbox_bucket"),
        aksk_file=_as_path(storage_raw.get("aksk_file"), PROJECT_ROOT / "secret" / "360-aksk.txt") or PROJECT_ROOT / "secret" / "360-aksk.txt",
        ca_file=_as_path(storage_raw.get("ca_file"), PROJECT_ROOT / "secret" / "wfy-root-ca.pem"),
        verify_tls=str(storage_raw.get("verify_tls", True)).lower() not in {"0", "false", "no"},
    )
    runtime = RuntimeConfig(
        data_dir=_as_path(runtime_raw.get("data_dir"), PROJECT_ROOT / "data") or PROJECT_ROOT / "data",
        max_tasks=int(runtime_raw.get("max_tasks", 0) or 0),
        poll_interval_seconds=int(runtime_raw.get("poll_interval_seconds", 60) or 60),
        task_deadline_seconds=int(runtime_raw.get("task_deadline_seconds", 3600) or 3600),
        upload=str(runtime_raw.get("upload", False)).lower() in {"1", "true", "yes"},
        overwrite_local=str(runtime_raw.get("overwrite_local", False)).lower() in {"1", "true", "yes"},
    )
    return AppConfig(storage=storage, runtime=runtime)


def with_runtime_overrides(
    config: AppConfig,
    *,
    max_tasks: int | None = None,
    upload: bool | None = None,
    poll_interval_seconds: int | None = None,
) -> AppConfig:
    return AppConfig(
        storage=config.storage,
        runtime=RuntimeConfig(
            data_dir=config.runtime.data_dir,
            max_tasks=config.runtime.max_tasks if max_tasks is None else max_tasks,
            poll_interval_seconds=config.runtime.poll_interval_seconds if poll_interval_seconds is None else poll_interval_seconds,
            task_deadline_seconds=config.runtime.task_deadline_seconds,
            upload=config.runtime.upload if upload is None else upload,
            overwrite_local=config.runtime.overwrite_local,
        ),
    )
