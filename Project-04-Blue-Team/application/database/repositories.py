from __future__ import annotations

from database.db import SessionLocal, init_db
from database.orm_models import EvidenceHashRecord, InvestigationRecord
from models.schemas import InvestigationBundle


class InvestigationRepository:
    def __init__(self) -> None:
        init_db()

    def save(self, bundle: InvestigationBundle) -> None:
        with SessionLocal.begin() as session:
            record = InvestigationRecord(
                investigation_id=bundle.investigation_id,
                name=bundle.name,
                analyst=bundle.analyst,
                hostname=bundle.hostname,
                environment=bundle.environment,
                log_year=bundle.log_year,
                payload=bundle.model_dump(mode="json"),
            )
            session.merge(record)
            if bundle.file_scan:
                session.merge(
                    EvidenceHashRecord(
                        sha256=bundle.file_scan.sha256,
                        investigation_id=bundle.investigation_id,
                        filename=bundle.file_scan.original_filename,
                    )
                )

    def list(self) -> list[InvestigationBundle]:
        with SessionLocal() as session:
            rows = session.query(InvestigationRecord).order_by(InvestigationRecord.created_at.desc()).all()
            return [InvestigationBundle.model_validate(row.payload) for row in rows]

    def duplicate_for_sha256(self, sha256: str) -> str | None:
        with SessionLocal() as session:
            row = session.get(EvidenceHashRecord, sha256)
            return row.investigation_id if row else None

    def delete(self, investigation_id: str) -> None:
        with SessionLocal.begin() as session:
            row = session.get(InvestigationRecord, investigation_id)
            if row:
                session.delete(row)
