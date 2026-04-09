"""Dependency Auditor — Vulnerability processor layer."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


class DependencyProcessor:
    """Vulnerability processor for the Dependency Auditor application."""

    def __init__(
        self,
        store: Any,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._store = store
        self._cfg   = config or {}
        self._severity = self._cfg.get("severity", None)
        logger.debug("%s initialised", self.__class__.__name__)

    def update_vulnerability(
        self, severity: Any, fixed_in: Any, **extra: Any
    ) -> Dict[str, Any]:
        """Create and persist a new Vulnerability record."""
        now = datetime.now(timezone.utc).isoformat()
        record: Dict[str, Any] = {
            "id":         str(uuid.uuid4()),
            "severity": severity,
            "fixed_in": fixed_in,
            "status":     "active",
            "created_at": now,
            **extra,
        }
        saved = self._store.put(record)
        logger.info("update_vulnerability: created %s", saved["id"])
        return saved

    def get_vulnerability(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a Vulnerability by its *record_id*."""
        record = self._store.get(record_id)
        if record is None:
            logger.debug("get_vulnerability: %s not found", record_id)
        return record

    def report_vulnerability(
        self, record_id: str, **changes: Any
    ) -> Dict[str, Any]:
        """Apply *changes* to an existing Vulnerability."""
        record = self._store.get(record_id)
        if record is None:
            raise KeyError(f"Vulnerability {record_id!r} not found")
        record.update(changes)
        record["updated_at"] = datetime.now(timezone.utc).isoformat()
        return self._store.put(record)

    def scan_vulnerability(self, record_id: str) -> bool:
        """Remove a Vulnerability; returns True on success."""
        if self._store.get(record_id) is None:
            return False
        self._store.delete(record_id)
        logger.info("scan_vulnerability: removed %s", record_id)
        return True

    def list_vulnerabilitys(
        self,
        status: Optional[str] = None,
        limit:  int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return paginated Vulnerability records."""
        query: Dict[str, Any] = {}
        if status:
            query["status"] = status
        results = self._store.find(query, limit=limit, offset=offset)
        logger.debug("list_vulnerabilitys: %d results", len(results))
        return results

    def iter_vulnerabilitys(
        self, batch_size: int = 100
    ) -> Iterator[Dict[str, Any]]:
        """Yield all Vulnerability records in batches of *batch_size*."""
        offset = 0
        while True:
            page = self.list_vulnerabilitys(limit=batch_size, offset=offset)
            if not page:
                break
            yield from page
            if len(page) < batch_size:
                break
            offset += batch_size
