from __future__ import annotations

from app.audit.ledger import append_event, verify_chain
from app.models import AuditEvent


def test_chain_is_intact_after_normal_appends(db_session):
    append_event(db_session, "test_event_a", None, {"n": 1})
    append_event(db_session, "test_event_b", None, {"n": 2})
    status = verify_chain(db_session)
    assert status["intact"] is True
    assert status["first_invalid_seq"] is None


def test_chain_detects_evidence_tampering(db_session):
    append_event(db_session, "test_event_c", None, {"original": True})
    event = db_session.query(AuditEvent).order_by(AuditEvent.seq.desc()).first()

    event.evidence = {"original": False}  # tamper with a past entry's payload
    db_session.commit()

    status = verify_chain(db_session)
    assert status["intact"] is False
    assert status["first_invalid_seq"] == event.seq


def test_chain_detects_deleted_entry(db_session):
    append_event(db_session, "test_event_d", None, {"k": "v1"})
    append_event(db_session, "test_event_e", None, {"k": "v2"})
    middle = (
        db_session.query(AuditEvent)
        .filter(AuditEvent.event_type == "test_event_d")
        .order_by(AuditEvent.seq.desc())
        .first()
    )
    db_session.delete(middle)
    db_session.commit()

    status = verify_chain(db_session)
    assert status["intact"] is False


def test_chain_includes_explicit_limitation_disclaimer(db_session):
    status = verify_chain(db_session)
    assert "cannot prevent" in status["limitation"]
