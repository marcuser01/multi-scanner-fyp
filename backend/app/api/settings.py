from fastapi import APIRouter, Body, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.database import SystemConfig, AuditLog
from app.core.security import encrypt_secret
from app.api.dependencies import require_admin

router = APIRouter()

@router.post("/llm-key")
async def save_llm_key(key: str = Body(..., embed=True), db: Session = Depends(get_db), admin = Depends(require_admin)):
    encrypted = encrypt_secret(key)
    conf = db.query(SystemConfig).filter(SystemConfig.key_name == "OPENROUTER_API_KEY").first()
    if conf:
        conf.encrypted_value = encrypted
    else:
        db.add(SystemConfig(key_name="OPENROUTER_API_KEY", encrypted_value=encrypted))
        
    db.add(AuditLog(user_id=admin.id, action="UPDATED_SYSTEM_SECRET", target="OPENROUTER_API_KEY"))
    db.commit()
    return {"message": "API Key securely vaulted"}

@router.get("/has-key")
async def check_key(db: Session = Depends(get_db), admin = Depends(require_admin)):
    conf = db.query(SystemConfig).filter(SystemConfig.key_name == "OPENROUTER_API_KEY").first()
    return {"has_key": conf is not None}