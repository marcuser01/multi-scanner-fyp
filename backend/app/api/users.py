from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from app.core.database import get_db
from app.models.database import User, AuditLog, Scan
from app.api.dependencies import require_admin, get_current_user

router = APIRouter()

class UserUpdate(BaseModel):
    role: str
    is_active: bool

@router.get("")
async def list_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "role": u.role, "is_active": u.is_active, "created_at": u.created_at} for u in users]

@router.patch("/{user_id}")
async def update_user(user_id: int, data: UserUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user: raise HTTPException(status_code=404, detail="User not found")
    # BUSINESS LOGIC GUARD: Prevent Admin self-demotion or self-deactivation
    if target_user.id == admin.id:
        if data.role != "ADMIN" or not data.is_active:
            raise HTTPException(status_code=400, detail="You cannot demote or suspend your own Admin account.")
        
    target_user.role = data.role
    target_user.is_active = data.is_active
    db.add(AuditLog(user_id=admin.id, action="UPDATED_USER_WORKFLOW", target=target_user.username, details=f"Role: {data.role} | Active: {data.is_active}"))
    db.commit()
    return {"message": "User updated"}

@router.delete("/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user: 
        raise HTTPException(status_code=404, detail="User not found")
    
    # BUSINESS LOGIC GUARD: Cannot self-delete
    if target_user.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own active Admin session.")
        
    # LEAST PRIVILEGE / AUDIT SAFE: Orphan their scans instead of cascading delete
    db.query(Scan).filter(Scan.owner_id == target_user.id).update({"owner_id": None})
    
    db.delete(target_user)
    db.add(AuditLog(user_id=admin.id, action="DELETED_USER", target=target_user.username))
    db.commit()
    return {"message": "User successfully deleted from platform"}