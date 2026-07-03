from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.database import AuditLog, User
from app.api.dependencies import require_admin

router = APIRouter()

@router.get("")
async def get_audit_logs(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    # Fetch the last 100 system events, joining the User table to get the username
    logs = db.query(AuditLog, User.username)\
             .outerjoin(User, AuditLog.user_id == User.id)\
             .order_by(AuditLog.timestamp.desc())\
             .limit(100).all()
             
    return [
        {
            "id": log.AuditLog.id,
            "timestamp": log.AuditLog.timestamp,
            "username": log.username or "SYSTEM",
            "action": log.AuditLog.action,
            "target": log.AuditLog.target,
            "details": log.AuditLog.details
        }
        for log in logs
    ]