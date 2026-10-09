from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditEvent, Certificate, Operation

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)) -> dict:
    total_operations = db.query(func.count(Operation.id)).scalar() or 0
    verified = db.query(func.count(Operation.id)).filter(Operation.verification_status == "verified").scalar() or 0
    failed = db.query(func.count(Operation.id)).filter(Operation.verification_status == "failed").scalar() or 0
    inconclusive = (
        db.query(func.count(Operation.id)).filter(Operation.verification_status == "inconclusive").scalar() or 0
    )
    image_ops = db.query(func.count(Operation.id)).filter(Operation.target_type == "image").scalar() or 0
    physical_ops = db.query(func.count(Operation.id)).filter(Operation.target_type == "physical").scalar() or 0
    total_certificates = db.query(func.count(Certificate.id)).scalar() or 0
    total_audit_events = db.query(func.count(AuditEvent.seq)).scalar() or 0

    recent = (
        db.query(Operation)
        .order_by(Operation.created_at.desc())
        .limit(10)
        .all()
    )

    return {
        "total_operations": total_operations,
        "verified_count": verified,
        "failed_count": failed,
        "inconclusive_count": inconclusive,
        "image_based_operations": image_ops,
        "physical_operations": physical_ops,
        "total_certificates": total_certificates,
        "total_audit_events": total_audit_events,
        "recent_operations": [
            {
                "id": op.id,
                "target_type": op.target_type,
                "target_label": op.target_label,
                "status": op.status,
                "verification_status": op.verification_status,
                "simulation_only": op.simulation_only,
                "created_at": op.created_at.isoformat(),
            }
            for op in recent
        ],
    }
