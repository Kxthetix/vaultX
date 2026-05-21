"""VaultX Reports Router"""
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
from backend.database import get_db, Scan, Report, Finding
import uuid, os
from backend.config import settings

router = APIRouter()

class ReportRequest(BaseModel):
    scan_id: str
    template: str = "hackerone"
    format: str = "pdf"

@router.post("/")
async def generate_report(req: ReportRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == req.scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    report_id = str(uuid.uuid4())
    report = Report(id=report_id, scan_id=req.scan_id, format=req.format, template=req.template)
    db.add(report)
    await db.commit()
    return {"report_id": report_id, "status": "generating"}

@router.get("/{report_id}/download")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report or not report.file_path:
        raise HTTPException(404, "Report not ready")
    if not os.path.exists(report.file_path):
        raise HTTPException(404, "Report file not found")
    return FileResponse(report.file_path, media_type="application/pdf", filename=f"vaultx_report_{report_id}.pdf")
