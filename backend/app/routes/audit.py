from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.audit.ledger import verify_chain
from app.database import get_db
from app.models import AuditEvent
from app.schemas import AuditChainStatus, AuditEventOut

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("", response_model=list[AuditEventOut])
def list_audit_events(db: Session = Depends(get_db)) -> list[AuditEventOut]:
    events = db.query(AuditEvent).order_by(AuditEvent.seq.asc()).all()
    return [AuditEventOut.model_validate(e) for e in events]


@router.get("/verify-chain", response_model=AuditChainStatus)
def get_chain_status(db: Session = Depends(get_db)) -> AuditChainStatus:
    return AuditChainStatus(**verify_chain(db))
