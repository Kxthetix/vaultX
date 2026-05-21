"""VaultX Findings Router"""
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.database import get_db, Finding, Severity
router = APIRouter()

@router.get("/")
async def list_findings(scan_id: str = None, severity: str = None, db: AsyncSession = Depends(get_db)):
    q = select(Finding)
    if scan_id:
        q = q.where(Finding.scan_id == scan_id)
    if severity:
        q = q.where(Finding.severity == severity)
    result = await db.execute(q.order_by(Finding.cvss_score.desc()).limit(200))
    findings = result.scalars().all()
    return findings

@router.get("/{finding_id}")
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "Finding not found")
    return f
