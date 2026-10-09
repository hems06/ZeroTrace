from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.audit.ledger import append_event
from app.certificates.generator import create_certificate, verify_certificate
from app.database import get_db
from app.models import Certificate, Operation
from app.schemas import CertificateOut, CertificateVerifyOut
from app.security import require_operator

router = APIRouter(prefix="/api/certificates", tags=["certificates"])


@router.get("", response_model=list[CertificateOut])
def list_certificates(db: Session = Depends(get_db)) -> list[CertificateOut]:
    certs = db.query(Certificate).order_by(Certificate.issued_at.desc()).all()
    return [CertificateOut.model_validate(c) for c in certs]


@router.get("/{certificate_id}", response_model=CertificateOut)
def get_certificate(certificate_id: str, db: Session = Depends(get_db)) -> CertificateOut:
    cert = db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Certificate not found.")
    return CertificateOut.model_validate(cert)


@router.get("/{certificate_id}/download")
def download_certificate(certificate_id: str, db: Session = Depends(get_db)):
    cert = db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Certificate not found.")
    return FileResponse(cert.pdf_path, media_type="application/pdf", filename=f"{certificate_id}.pdf")


@router.post("/{certificate_id}/verify", response_model=CertificateVerifyOut)
def verify_certificate_endpoint(certificate_id: str, db: Session = Depends(get_db)) -> CertificateVerifyOut:
    cert = db.get(Certificate, certificate_id)
    if cert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Certificate not found.")
    result = verify_certificate(db, cert)
    return CertificateVerifyOut(**result)


@router.post("/for-operation/{operation_id}", response_model=CertificateOut, status_code=status.HTTP_201_CREATED)
def create_certificate_for_operation(
    operation_id: str,
    db: Session = Depends(get_db),
    operator_id: str = Depends(require_operator),
) -> CertificateOut:
    operation = db.get(Operation, operation_id)
    if operation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Operation not found.")
    if operation.status not in ("completed", "failed", "blocked_safety_disabled", "blocked_not_implemented"):
        raise HTTPException(status.HTTP_409_CONFLICT, "Operation has not finished executing yet.")

    cert = create_certificate(db, operation)
    append_event(
        db,
        "certificate_issued",
        operation.id,
        {"certificate_id": cert.id, "final_status": cert.final_status, "operator_id": operator_id},
    )
    return CertificateOut.model_validate(cert)
