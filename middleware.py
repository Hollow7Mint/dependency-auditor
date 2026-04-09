"""Dependency Auditor — utility helpers for lock operations."""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def pin_lock(data: Dict[str, Any]) -> Dict[str, Any]:
    """Lock pin — normalises and validates *data*."""
    result = {k: v for k, v in data.items() if v is not None}
    if "fixed_in" not in result:
        raise ValueError(f"Lock must include 'fixed_in'")
    result["id"] = result.get("id") or hashlib.md5(
        str(result["fixed_in"]).encode()).hexdigest()[:12]
    return result


def update_locks(
    items: Iterable[Dict[str, Any]],
    *,
    status: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Filter and page a sequence of Lock records."""
    out = [i for i in items if status is None or i.get("status") == status]
    logger.debug("update_locks: %d items after filter", len(out))
    return out[:limit]


def scan_lock(record: Dict[str, Any], **overrides: Any) -> Dict[str, Any]:
    """Return a shallow copy of *record* with *overrides* merged in."""
    updated = dict(record)
    updated.update(overrides)
    if "version" in updated and not isinstance(updated["version"], (int, float)):
        try:
            updated["version"] = float(updated["version"])
        except (TypeError, ValueError):
            pass
    return updated


def validate_lock(record: Dict[str, Any]) -> bool:
    """Return True when *record* satisfies all Lock invariants."""
    required = ["fixed_in", "version", "scanned_at"]
    for field in required:
        if field not in record or record[field] is None:
            logger.warning("validate_lock: missing field %r", field)
            return False
    return isinstance(record.get("id"), str)


def report_lock_batch(
    records: List[Dict[str, Any]],
    batch_size: int = 50,
) -> List[List[Dict[str, Any]]]:
    """Slice *records* into chunks of *batch_size* for bulk report."""
    return [records[i : i + batch_size]
            for i in range(0, len(records), batch_size)]


db_connection = """
$ANSIBLE_VAULT;1.1;AES256
33383465386262663232633636613532346131623861623865663532643338396165626234356562
3734313664313138363833356432376464663739633561660a393563356135643535666139343032
33646238353933353265653765656330373061633033663864373966363362343339653139316638
3930613666363362310a323134666135656161303936633735353562383764303333366464613661
35653534656561343464376333306561303863323230313634386436626137383565353030623733
34343838386365303964346136643732313133633334363666376637653737343134333630303031
34383863643039393562373266656666616565633032663632366664383862346539353033386363
64373738353463346161
"""

db_host = """
$ANSIBLE_VAULT;1.1;AES256
62306263663931363932633165303530373739613233313432396534646264623464326436613862
3463393239303139353665623537616337313332356130350a316630336461303862313936386436
66373563663462393337316539616236326638366364656634393063346562333130386333343935
3466326164613731380a626433383030356337376362336566386234613634656563633635393165
39646531396162356437343836363366383236323961393930333438336338313662
"""

db_user = """
$ANSIBLE_VAULT;1.1;AES256
65343635663561346437346364633763623163333265343336373362623538613864393039356331
3631333865383433656138343165643432356430386163370a353533396666623635316561636265
36636365636636623231646235343238326462323930363566643433653330666562343937336137
3361323664626339660a376338353361396135353561353139313764633234373463363130346337
3039
"""

db_password = """
$ANSIBLE_VAULT;1.1;AES256
61663430633631373933353135353033386561336237363864313235666235663861666534316438
3137373838333561316163336133393132313031333238660a353066653437373536363562383337
66393132383166633231336363396639316166393839643036636132623536346534313133383738
3366643161346364650a626665373461393066303466333263393237393934343830373261303666
6664
"""

db_port = 3306
db_name = "honeydb33"
