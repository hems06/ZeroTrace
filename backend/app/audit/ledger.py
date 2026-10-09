"""Hash-linked, append-only audit ledger.

Each event's entry_hash = SHA-256(prev_hash || event_type || timestamp ||
operation_id || canonical evidence JSON). Because every entry commits to the
previous entry's hash, altering or deleting a past row breaks the chain for
every row after it, so tampering is detectable by replaying the chain.

Important limitation (documented, not hidden): hash chaining only detects
tampering by re-verifying the chain. It does NOT prevent an attacker with
direct database write access from regenerating a consistent chain from
scratch after altering history. Real tamper-*prevention* needs the chain
anchored outside this database (e.g. periodic external notarization, WORM
storage, or a separate signing authority) -- out of scope for this build,
and verify_chain() exists precisely to make that boundary visible to
operators rather than imply a stronger guarantee.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import AuditEvent

GENESIS_HASH = "0" * 64


def _entry_hash(prev_hash: str, event_type: str, timestamp: datetime, operation_id: str | None, evidence: dict) -> str:
    canonical = json.dumps(
        {
            "prev_hash": prev_hash,
            "event_type": event_type,
            "timestamp": timestamp.isoformat(),
            "operation_id": operation_id,
            "evidence": evidence,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _latest_hash(db: Session) -> str:
    last = db.query(AuditEvent).order_by(AuditEvent.seq.desc()).first()
    return last.entry_hash if last else GENESIS_HASH


def append_event(db: Session, event_type: str, operation_id: str | None, evidence: dict) -> AuditEvent:
    prev_hash = _latest_hash(db)
    timestamp = datetime.utcnow()
    entry_hash = _entry_hash(prev_hash, event_type, timestamp, operation_id, evidence)
    event = AuditEvent(
        operation_id=operation_id,
        event_type=event_type,
        timestamp=timestamp,
        evidence=evidence,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def verify_chain(db: Session) -> dict:
    """Replay the full chain and report the first point of tampering, if any."""
    events = db.query(AuditEvent).order_by(AuditEvent.seq.asc()).all()
    prev_hash = GENESIS_HASH
    for event in events:
        expected = _entry_hash(prev_hash, event.event_type, event.timestamp, event.operation_id, event.evidence)
        if event.prev_hash != prev_hash or event.entry_hash != expected:
            return {
                "intact": False,
                "total_events": len(events),
                "first_invalid_seq": event.seq,
                "limitation": (
                    "Hash chaining detects tampering via replay; it cannot prevent "
                    "an attacker with full database access from rebuilding a "
                    "consistent chain after the fact."
                ),
            }
        prev_hash = event.entry_hash
    return {
        "intact": True,
        "total_events": len(events),
        "first_invalid_seq": None,
        "limitation": (
            "Hash chaining detects tampering via replay; it cannot prevent "
            "an attacker with full database access from rebuilding a "
            "consistent chain after the fact."
        ),
    }
