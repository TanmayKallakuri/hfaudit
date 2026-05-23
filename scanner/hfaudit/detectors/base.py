from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from hfaudit.reporting.finding import Finding


class BaseDetector(ABC):
    """Abstract base for all detectors. Each detector maps to one or more rule IDs."""

    @property
    @abstractmethod
    def rule_ids(self) -> list[str]:
        """Rule IDs this detector can emit."""

    @abstractmethod
    def detect(self, parsed_model: Any) -> list[Finding]:
        """Run detection on a parsed model artifact and return findings."""
