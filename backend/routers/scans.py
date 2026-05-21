"""VaultX Scans Router"""
from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from pydantic import BaseModel, validator
from typing import Optional, List
import uuid, re, ipaddress
from datetime import datetime
from backend.database import get_db, Scan, ScanStatus
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

router = APIRouter()

BLOCKED_RANGES = ["localhost","127.","192.168.","10.","172.16.","0.0.0.0","::1"]

class ScanRequest(BaseModel):
    target: str
    scope_domains: List[str] = []
    excluded_domains: List[str] = []
    authorized: bool
    authorization_proof: Optional[str] = None
    scan_config: dict = {}
    ai_provider: str = "claude"

    @validator("target")
    def validate_target(cls, v):
        for b in BLOCKED_RANGES:
            if b in v.lower():
                raise ValueError(f"Target is in blocked range")
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$', v.split(":")[0]):
            raise ValueError("Invalid target format")
        return v

    @validator("authorized")
    def must_be_authorized(cls, v):
        if not v:
            raise ValueError("Authorization is required before scanning")
        return v

@router.post("/")
async def create_scan(req: ScanRequest, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    scan = Scan(
        id=str(uuid.uuid4()),
        target=req.target,
        scope={"domains": req.scope_domains or [req.target], "excluded": req.excluded_domains},
        authorized=req.authorized,
        authorization_proof=req.authorization_proof,
        scan_config=req.scan_config,
        ai_provider=req.ai_provider,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    # In production: background_tasks.add_task(run_scan_pipeline, scan.id)
    return {"scan_id": scan.id, "status": "pending", "message": "Scan queued"}

@router.get("/")
async def list_scans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(50))
    scans = result.scalars().all()
    return [{"id": s.id, "target": s.target, "status": s.status, "created_at": s.created_at,
             "total_findings": s.total_findings, "risk_score": s.risk_score} for s in scans]

@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan

@router.delete("/{scan_id}")
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan.status = ScanStatus.CANCELLED
    await db.commit()
    return {"message": "Scan cancelled"}
