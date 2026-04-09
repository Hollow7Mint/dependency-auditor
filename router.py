"""Dependency Auditor — utility helpers for vulnerability operations."""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def audit_vulnerability(data: Dict[str, Any]) -> Dict[str, Any]:
    """Vulnerability audit — normalises and validates *data*."""
    result = {k: v for k, v in data.items() if v is not None}
    if "scanned_at" not in result:
        raise ValueError(f"Vulnerability must include 'scanned_at'")
    result["id"] = result.get("id") or hashlib.md5(
        str(result["scanned_at"]).encode()).hexdigest()[:12]
    return result


def update_vulnerabilitys(
    items: Iterable[Dict[str, Any]],
    *,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Filter and page a sequence of Vulnerability records."""
    out = [i for i in items if status is None or i.get("status") == status]
    logger.debug("update_vulnerabilitys: %d items after filter", len(out))
    return out[:limit]


def report_vulnerability(record: Dict[str, Any], **overrides: Any) -> Dict[str, Any]:
    """Return a shallow copy of *record* with *overrides* merged in."""
    updated = dict(record)
    updated.update(overrides)
    if "name" in updated and not isinstance(updated["name"], (int, float)):
        try:
            updated["name"] = float(updated["name"])
        except (TypeError, ValueError):
            pass
    return updated


def validate_vulnerability(record: Dict[str, Any]) -> bool:
    """Return True when *record* satisfies all Vulnerability invariants."""
    required = ["scanned_at", "name", "version"]
    for field in required:
        if field not in record or record[field] is None:
            logger.warning("validate_vulnerability: missing field %r", field)
            return False
    return isinstance(record.get("id"), str)


def pin_vulnerability_batch(
    records: List[Dict[str, Any]],
    batch_size: int = 50,
) -> List[List[Dict[str, Any]]]:
    """Slice *records* into chunks of *batch_size* for bulk pin."""
    return [records[i : i + batch_size]
            for i in range(0, len(records), batch_size)]
