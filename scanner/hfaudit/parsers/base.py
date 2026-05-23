from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseParser(ABC):
    """Abstract base for format-specific model parsers."""

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """File extensions this parser handles (e.g. ['.pkl', '.pt'])."""

    @abstractmethod
    def parse(self, data: bytes, file_path: str) -> Any:
        """Parse raw bytes into a structured representation for detectors."""
