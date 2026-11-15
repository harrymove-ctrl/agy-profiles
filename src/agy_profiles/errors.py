"""Structured error contract for CLI, MCP, and local web endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional


class ToolError(Exception):
    """Typed operational or security error with explicit remediation guidance."""

    def __init__(
        self,
        code: str,
        message: str,
        remediation: str = "",
        details: Optional[Dict[str, Any]] = None,
        http_status: int = 400,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation
        self.details: Dict[str, Any] = details if details is not None else {}
        self.http_status = http_status

    def to_dict(self) -> Dict[str, Any]:
        """Serialize error into a stable structured envelope."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "remediation": self.remediation,
                "details": self.details,
            }
        }
