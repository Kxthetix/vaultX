"""VaultX Health Router"""
from fastapi import APIRouter
from datetime import datetime
router = APIRouter()

@router.get("/")
async def health():
    return {"status": "ok", "service": "VaultX VAPT Platform", "timestamp": datetime.utcnow().isoformat()}
