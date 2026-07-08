from __future__ import annotations

from typing import Any


class ExternalApiClient:
    def __init__(self, *, timeout: float = 15.0):
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Missing httpx. Install dependencies with: python3 -m pip install -r requirements.txt") from exc
        self._httpx = httpx
        self._client = httpx.Client(timeout=timeout)

    def get_json(self, url: str, **kwargs: Any) -> Any:
        response = self._client.get(url, **kwargs)
        response.raise_for_status()
        return response.json()

    def post_json(self, url: str, payload: dict[str, Any], **kwargs: Any) -> Any:
        response = self._client.post(url, json=payload, **kwargs)
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ExternalApiClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
