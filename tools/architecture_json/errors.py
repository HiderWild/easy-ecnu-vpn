"""Stable error contract for architecture JSON operations."""

from __future__ import annotations

from typing import Any


class ArchitectureQueryError(Exception):
    """A machine-readable operation failure with a stable process exit code."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        exit_code: int,
        location: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.location = location
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.location is not None:
            error["location"] = self.location
        if self.details:
            error["details"] = self.details
        return error
