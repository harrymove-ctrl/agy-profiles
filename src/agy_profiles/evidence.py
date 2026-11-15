"""Deterministic Evidence records and security obligation ledger types."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List


def utc_now_iso() -> str:
    """Return current UTC timestamp in second-precision ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def canonical_json(data: Any) -> str:
    """Serialize data deterministically for content-addressed digests."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_sha256(data: Any) -> str:
    """Compute lowercase SHA-256 hex digest over canonical JSON serialization."""
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


@dataclass
class EvidenceRecord:
    """Structured inspection or verification finding with explicit boundaries."""

    operation: str
    authority: str
    confidence: str
    summary: str
    facts: Dict[str, Any]
    limitations: List[str] = field(default_factory=list)
    observed_at: str = field(default_factory=utc_now_iso)
    evidence_id: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_id:
            payload = {
                "operation": self.operation,
                "authority": self.authority,
                "confidence": self.confidence,
                "summary": self.summary,
                "facts": self.facts,
                "limitations": self.limitations,
            }
            self.evidence_id = "ev_" + compute_sha256(payload)[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to JSON-safe dictionary."""
        return {
            "evidence_id": self.evidence_id,
            "operation": self.operation,
            "authority": self.authority,
            "confidence": self.confidence,
            "summary": self.summary,
            "facts": self.facts,
            "limitations": self.limitations,
            "observed_at": self.observed_at,
        }


@dataclass
class ObligationItem:
    """Single security or isolation invariant backed by an owner digest and proof."""

    obligation_id: str
    title: str
    status: str
    owner_module: str
    module_sha256: str
    cases_checked: List[str]
    detail: str
    evidence_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert obligation item to JSON-safe dictionary."""
        return {
            "obligation_id": self.obligation_id,
            "title": self.title,
            "status": self.status,
            "owner_module": self.owner_module,
            "module_sha256": self.module_sha256,
            "cases_checked": self.cases_checked,
            "detail": self.detail,
            "evidence_id": self.evidence_id,
        }


@dataclass
class ObligationReport:
    """Aggregated obligation closure ledger for self-verification checks."""

    ledger_id: str
    verified_at: str
    summary: Dict[str, int]
    items: List[ObligationItem]
    evidence: List[EvidenceRecord]

    def to_dict(self) -> Dict[str, Any]:
        """Convert complete obligation report into JSON-safe dictionary."""
        return {
            "ledger_id": self.ledger_id,
            "verified_at": self.verified_at,
            "summary": self.summary,
            "items": [item.to_dict() for item in self.items],
            "evidence": [ev.to_dict() for ev in self.evidence],
        }
