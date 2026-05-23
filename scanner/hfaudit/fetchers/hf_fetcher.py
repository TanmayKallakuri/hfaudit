from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import httpx
from huggingface_hub import HfApi, hf_hub_download
from huggingface_hub.errors import (
    HfHubHTTPError,
    RepositoryNotFoundError,
)

from hfaudit.fetchers.exceptions import FetchError, ModelNotFoundError, RateLimitError

_DEFAULT_HEADER_BYTES: Final[int] = 1_048_576  # 1 MB
_HF_ENDPOINT: Final[str] = "https://huggingface.co"


@dataclass(frozen=True)
class ModelFile:
    path: str
    size: int
    is_lfs: bool
    oid: str | None


@dataclass(frozen=True)
class FetchResult:
    model_id: str
    files: list[ModelFile] = field(default_factory=list)


@dataclass(frozen=True)
class FileContent:
    path: str
    data: bytes
    is_partial: bool
    total_size: int


def _resolve_token() -> str | None:
    return os.environ.get("HF_TOKEN") or None


def _extract_retry_after(exc: HfHubHTTPError) -> float | None:
    resp = getattr(exc, "response", None)
    if resp is None:
        return None
    raw = resp.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return float(raw)
    except (ValueError, TypeError):
        return None


class HFFetcher:
    """Fetches model metadata and file content from HuggingFace Hub."""

    def __init__(self, token: str | None = None) -> None:
        self._token = token or _resolve_token()
        self._api = HfApi(token=self._token)

    def list_model_files(self, model_id: str) -> FetchResult:
        try:
            info = self._api.model_info(model_id, files_metadata=True, token=self._token)
        except RepositoryNotFoundError as exc:
            raise ModelNotFoundError(model_id) from exc
        except HfHubHTTPError as exc:
            resp = getattr(exc, "response", None)
            if resp is not None and resp.status_code == 429:
                raise RateLimitError(_extract_retry_after(exc)) from exc
            raise FetchError(f"Failed to fetch model info for {model_id}: {exc}") from exc

        files: list[ModelFile] = []
        for sibling in info.siblings or []:
            lfs = sibling.lfs
            is_lfs = lfs is not None
            oid = lfs.sha256 if lfs is not None else sibling.blob_id
            size = (lfs.size if lfs is not None else sibling.size) or 0
            files.append(ModelFile(path=sibling.rfilename, size=size, is_lfs=is_lfs, oid=oid))

        return FetchResult(model_id=model_id, files=files)

    def fetch_file_header(
        self,
        model_id: str,
        file_path: str,
        max_bytes: int = _DEFAULT_HEADER_BYTES,
    ) -> FileContent:
        url = f"{_HF_ENDPOINT}/{model_id}/resolve/main/{file_path}"
        headers: dict[str, str] = {"Range": f"bytes=0-{max_bytes - 1}"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            with httpx.Client(follow_redirects=True, timeout=30.0) as client:
                resp = client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise FetchError(
                f"Network error fetching header for {model_id}/{file_path}: {exc}"
            ) from exc

        if resp.status_code == 404:
            raise ModelNotFoundError(model_id, detail=f"file {file_path} not found")
        if resp.status_code == 429:
            raw_retry = resp.headers.get("Retry-After")
            retry_after: float | None = None
            if raw_retry:
                try:
                    retry_after = float(raw_retry)
                except (ValueError, TypeError):
                    pass
            raise RateLimitError(retry_after)
        if resp.status_code >= 400:
            raise FetchError(
                f"HTTP {resp.status_code} fetching {model_id}/{file_path}"
            )

        data = resp.content
        total_size = _parse_total_size(resp, len(data))
        is_partial = resp.status_code == 206

        return FileContent(
            path=file_path,
            data=data,
            is_partial=is_partial,
            total_size=total_size,
        )

    def fetch_file(self, model_id: str, file_path: str) -> FileContent:
        try:
            local_path = hf_hub_download(
                repo_id=model_id,
                filename=file_path,
                token=self._token,
            )
        except RepositoryNotFoundError as exc:
            raise ModelNotFoundError(model_id) from exc
        except HfHubHTTPError as exc:
            resp = getattr(exc, "response", None)
            if resp is not None and resp.status_code == 429:
                raise RateLimitError(_extract_retry_after(exc)) from exc
            raise FetchError(
                f"Failed to download {model_id}/{file_path}: {exc}"
            ) from exc

        if not isinstance(local_path, str):
            raise FetchError(f"Unexpected return from hf_hub_download for {model_id}/{file_path}")
        path_obj = Path(local_path)
        data = path_obj.read_bytes()
        return FileContent(
            path=file_path,
            data=data,
            is_partial=False,
            total_size=len(data),
        )


def _parse_total_size(resp: httpx.Response, data_len: int) -> int:
    """Extract total file size from Content-Range header, falling back to data length."""
    content_range = resp.headers.get("Content-Range", "")
    if "/" in content_range:
        total_str = content_range.rsplit("/", 1)[-1]
        if total_str != "*":
            try:
                return int(total_str)
            except ValueError:
                pass
    return data_len
