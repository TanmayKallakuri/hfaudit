from __future__ import annotations


class FetchError(Exception):
    """Base exception for all fetcher errors."""


class ModelNotFoundError(FetchError):
    """Raised when the requested model does not exist or is inaccessible."""

    def __init__(self, model_id: str, detail: str = "") -> None:
        self.model_id = model_id
        msg = f"Model not found: {model_id}"
        if detail:
            msg = f"{msg} ({detail})"
        super().__init__(msg)


class RateLimitError(FetchError):
    """Raised when HuggingFace returns HTTP 429."""

    def __init__(self, retry_after: float | None = None) -> None:
        self.retry_after = retry_after
        msg = "Rate limited by HuggingFace API"
        if retry_after is not None:
            msg = f"{msg} (retry after {retry_after}s)"
        super().__init__(msg)
