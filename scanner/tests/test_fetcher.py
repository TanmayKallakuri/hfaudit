from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest

from hfaudit.fetchers import (
    FetchError,
    FetchResult,
    FileContent,
    HFFetcher,
    ModelFile,
    ModelNotFoundError,
    RateLimitError,
)


def _make_httpx_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    resp = httpx.Response(
        status_code=status_code,
        headers=headers or {},
        content=b"",
    )
    resp._request = httpx.Request("GET", "https://huggingface.co/mock")  # noqa: SLF001
    return resp


# -- Helpers for building mock HF API objects --


@dataclass
class _FakeLfs:
    size: int
    sha256: str
    pointer_size: int


@dataclass
class _FakeSibling:
    rfilename: str
    size: int | None = None
    blob_id: str | None = None
    lfs: _FakeLfs | None = None


def _fake_model_info(siblings: list[_FakeSibling]) -> MagicMock:
    info = MagicMock()
    info.siblings = siblings
    return info


def _make_fetcher() -> tuple[HFFetcher, MagicMock]:
    """Build a fetcher with a mocked HfApi, returning both."""
    with patch("hfaudit.fetchers.hf_fetcher.HfApi") as mock_api_cls:
        mock_api = MagicMock()
        mock_api_cls.return_value = mock_api
        fetcher = HFFetcher()
    return fetcher, mock_api


# -- list_model_files --


class TestListModelFiles:
    def test_returns_structured_files(self) -> None:
        fetcher, mock_api = _make_fetcher()
        siblings = [
            _FakeSibling(rfilename="config.json", size=1024, blob_id="abc123"),
            _FakeSibling(
                rfilename="pytorch_model.bin",
                size=None,
                blob_id=None,
                lfs=_FakeLfs(size=500_000_000, sha256="deadbeef", pointer_size=132),
            ),
        ]
        mock_api.model_info.return_value = _fake_model_info(siblings)

        result = fetcher.list_model_files("user/test-model")

        assert isinstance(result, FetchResult)
        assert result.model_id == "user/test-model"
        assert len(result.files) == 2

        config = result.files[0]
        assert config.path == "config.json"
        assert config.size == 1024
        assert config.is_lfs is False
        assert config.oid == "abc123"

        weights = result.files[1]
        assert weights.path == "pytorch_model.bin"
        assert weights.size == 500_000_000
        assert weights.is_lfs is True
        assert weights.oid == "deadbeef"

    def test_empty_repo(self) -> None:
        fetcher, mock_api = _make_fetcher()
        mock_api.model_info.return_value = _fake_model_info([])
        result = fetcher.list_model_files("user/empty-model")
        assert result.files == []

    def test_none_siblings(self) -> None:
        fetcher, mock_api = _make_fetcher()
        info = MagicMock()
        info.siblings = None
        mock_api.model_info.return_value = info
        result = fetcher.list_model_files("user/no-siblings")
        assert result.files == []

    def test_model_not_found(self) -> None:
        from huggingface_hub.errors import RepositoryNotFoundError

        fetcher, mock_api = _make_fetcher()
        resp_404 = _make_httpx_response(404)
        mock_api.model_info.side_effect = RepositoryNotFoundError(
            "Not found", response=resp_404
        )
        with pytest.raises(ModelNotFoundError, match="nonexistent/model"):
            fetcher.list_model_files("nonexistent/model")

    def test_rate_limited(self) -> None:
        from huggingface_hub.errors import HfHubHTTPError

        fetcher, mock_api = _make_fetcher()
        resp_429 = _make_httpx_response(429, headers={"Retry-After": "60"})
        exc = HfHubHTTPError("rate limited", response=resp_429)
        mock_api.model_info.side_effect = exc

        with pytest.raises(RateLimitError) as exc_info:
            fetcher.list_model_files("user/model")
        assert exc_info.value.retry_after == 60.0

    def test_generic_http_error(self) -> None:
        from huggingface_hub.errors import HfHubHTTPError

        fetcher, mock_api = _make_fetcher()
        resp_500 = _make_httpx_response(500)
        exc = HfHubHTTPError("server error", response=resp_500)
        mock_api.model_info.side_effect = exc

        with pytest.raises(FetchError, match="Failed to fetch model info"):
            fetcher.list_model_files("user/model")

    def test_size_defaults_to_zero_when_none(self) -> None:
        fetcher, mock_api = _make_fetcher()
        siblings = [_FakeSibling(rfilename="readme.md", size=None, blob_id=None)]
        mock_api.model_info.return_value = _fake_model_info(siblings)
        result = fetcher.list_model_files("user/model")
        assert result.files[0].size == 0


# -- fetch_file_header --


def _patch_httpx_client(mock_resp: httpx.Response) -> Any:
    """Return a patch context that makes httpx.Client().get() return mock_resp."""
    ctx_mock = MagicMock()
    ctx_mock.get.return_value = mock_resp
    client_mock = MagicMock()
    client_mock.__enter__ = MagicMock(return_value=ctx_mock)
    client_mock.__exit__ = MagicMock(return_value=False)
    return patch(
        "hfaudit.fetchers.hf_fetcher.httpx.Client",
        return_value=client_mock,
    ), ctx_mock


class TestFetchFileHeader:
    def test_partial_content(self) -> None:
        fetcher, _ = _make_fetcher()
        fake_data = b"\x80\x05" + b"\x00" * 998
        mock_resp = httpx.Response(
            status_code=206,
            headers={
                "Content-Range": "bytes 0-999/5000000",
                "Content-Length": "1000",
            },
            content=fake_data,
        )
        patcher, _ = _patch_httpx_client(mock_resp)
        with patcher:
            result = fetcher.fetch_file_header("user/model", "model.bin", max_bytes=1000)

        assert isinstance(result, FileContent)
        assert result.path == "model.bin"
        assert result.is_partial is True
        assert result.total_size == 5_000_000
        assert len(result.data) == 1000

    def test_small_file_returns_full(self) -> None:
        fetcher, _ = _make_fetcher()
        fake_data = b"small content"
        mock_resp = httpx.Response(status_code=200, content=fake_data)
        patcher, _ = _patch_httpx_client(mock_resp)
        with patcher:
            result = fetcher.fetch_file_header("user/model", "config.json")

        assert result.is_partial is False
        assert result.total_size == len(fake_data)

    def test_404_raises_model_not_found(self) -> None:
        fetcher, _ = _make_fetcher()
        mock_resp = httpx.Response(status_code=404, content=b"")
        patcher, _ = _patch_httpx_client(mock_resp)
        with patcher:
            with pytest.raises(ModelNotFoundError, match="user/model"):
                fetcher.fetch_file_header("user/model", "missing.bin")

    def test_429_raises_rate_limit(self) -> None:
        fetcher, _ = _make_fetcher()
        mock_resp = httpx.Response(
            status_code=429, headers={"Retry-After": "30"}, content=b""
        )
        patcher, _ = _patch_httpx_client(mock_resp)
        with patcher:
            with pytest.raises(RateLimitError) as exc_info:
                fetcher.fetch_file_header("user/model", "model.bin")
            assert exc_info.value.retry_after == 30.0

    def test_network_error_wraps_in_fetch_error(self) -> None:
        fetcher, _ = _make_fetcher()
        ctx_mock = MagicMock()
        ctx_mock.get.side_effect = httpx.ConnectError("connection refused")
        client_mock = MagicMock()
        client_mock.__enter__ = MagicMock(return_value=ctx_mock)
        client_mock.__exit__ = MagicMock(return_value=False)
        with patch(
            "hfaudit.fetchers.hf_fetcher.httpx.Client", return_value=client_mock
        ):
            with pytest.raises(FetchError, match="Network error"):
                fetcher.fetch_file_header("user/model", "model.bin")

    def test_generic_http_error_status(self) -> None:
        fetcher, _ = _make_fetcher()
        mock_resp = httpx.Response(status_code=500, content=b"")
        patcher, _ = _patch_httpx_client(mock_resp)
        with patcher:
            with pytest.raises(FetchError, match="HTTP 500"):
                fetcher.fetch_file_header("user/model", "model.bin")

    def test_auth_header_sent_when_token_set(self) -> None:
        with patch("hfaudit.fetchers.hf_fetcher.HfApi"):
            with patch.dict("os.environ", {"HF_TOKEN": "hf_testtoken123"}):
                fetcher = HFFetcher()
        mock_resp = httpx.Response(status_code=200, content=b"data")
        patcher, ctx_mock = _patch_httpx_client(mock_resp)
        with patcher:
            fetcher.fetch_file_header("user/model", "model.bin")
            call_args = ctx_mock.get.call_args
            sent_headers: dict[str, str] = call_args[1]["headers"]
            assert sent_headers["Authorization"] == "Bearer hf_testtoken123"


# -- fetch_file --


class TestFetchFile:
    def test_returns_full_file(self, tmp_path: Path) -> None:
        fetcher, _ = _make_fetcher()
        fake_file = tmp_path / "model.bin"
        fake_file.write_bytes(b"\x80\x05" * 100)
        with patch("hfaudit.fetchers.hf_fetcher.hf_hub_download", return_value=str(fake_file)):
            result = fetcher.fetch_file("user/model", "model.bin")

        assert isinstance(result, FileContent)
        assert result.path == "model.bin"
        assert result.is_partial is False
        assert result.total_size == 200
        assert len(result.data) == 200

    def test_model_not_found(self) -> None:
        from huggingface_hub.errors import RepositoryNotFoundError

        fetcher, _ = _make_fetcher()
        resp_404 = _make_httpx_response(404)
        with patch(
            "hfaudit.fetchers.hf_fetcher.hf_hub_download",
            side_effect=RepositoryNotFoundError("Not found", response=resp_404),
        ):
            with pytest.raises(ModelNotFoundError):
                fetcher.fetch_file("nonexistent/model", "model.bin")

    def test_rate_limited(self) -> None:
        from huggingface_hub.errors import HfHubHTTPError

        fetcher, _ = _make_fetcher()
        resp_429 = _make_httpx_response(429, headers={"Retry-After": "120"})
        exc = HfHubHTTPError("rate limited", response=resp_429)
        with patch("hfaudit.fetchers.hf_fetcher.hf_hub_download", side_effect=exc):
            with pytest.raises(RateLimitError) as exc_info:
                fetcher.fetch_file("user/model", "model.bin")
            assert exc_info.value.retry_after == 120.0


# -- Dataclass invariants --


class TestDataclasses:
    def test_model_file_frozen(self) -> None:
        mf = ModelFile(path="x.bin", size=100, is_lfs=False, oid=None)
        with pytest.raises(AttributeError):
            mf.path = "y.bin"  # type: ignore[misc]

    def test_fetch_result_model_id(self) -> None:
        fr = FetchResult(model_id="a/b", files=[])
        assert fr.model_id == "a/b"

    def test_file_content_frozen(self) -> None:
        fc = FileContent(path="x.bin", data=b"", is_partial=False, total_size=0)
        with pytest.raises(AttributeError):
            fc.data = b"new"  # type: ignore[misc]


# -- Exception hierarchy --


class TestExceptions:
    def test_model_not_found_is_fetch_error(self) -> None:
        assert issubclass(ModelNotFoundError, FetchError)

    def test_rate_limit_is_fetch_error(self) -> None:
        assert issubclass(RateLimitError, FetchError)

    def test_model_not_found_message(self) -> None:
        exc = ModelNotFoundError("user/model", detail="private repo")
        assert "user/model" in str(exc)
        assert "private repo" in str(exc)

    def test_rate_limit_no_retry(self) -> None:
        exc = RateLimitError()
        assert exc.retry_after is None

    def test_rate_limit_with_retry(self) -> None:
        exc = RateLimitError(retry_after=45.0)
        assert exc.retry_after == 45.0
        assert "45.0" in str(exc)
