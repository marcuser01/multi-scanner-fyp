import os
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.core.database import get_db
from app.models.database import User, AuditLog
from app.core.security import get_password_hash, verify_password, create_access_token
from app.api.dependencies import get_current_user

router = APIRouter()

class UserAuth(BaseModel):
    username: str
    password: str

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

@router.get("/system-status")
async def system_status(db: Session = Depends(get_db)):
    has_users = db.query(User).first() is not None
    return {"is_setup": has_users}

@router.post("/register")
async def register(user: UserAuth, db: Session = Depends(get_db)):
    # SECURITY: Prevent Bcrypt 72-byte limit crashes & DoS attacks
    if len(user.password) > 64:
        raise HTTPException(status_code=400, detail="Password too long (max 64 characters)")
    if len(user.password) < 6:
        raise HTTPException(status_code=400, detail="Password too short (min 6 characters)")
        
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username taken")
    
    is_first = db.query(User).first() is None
    new_user = User(
        username=user.username,
        hashed_password=get_password_hash(user.password),
        role="ADMIN" if is_first else "DEVELOPER"
    )
    db.add(new_user)
    db.commit()
    return {"message": "User created", "role": new_user.role}

@router.post("/login")
async def login(response: Response, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or not user.is_active or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    token = create_access_token({"sub": user.username, "role": user.role})
    
    # SECURITY FIX: Enforce Strict SameSite and Secure cookies
    is_production = os.getenv("APP_ENV", "development") == "production"
    
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {token}", 
        httponly=True, 
        samesite="strict", # COMPLETELY mitigates CSRF since UI and API share the Nginx origin
        secure=is_production, # Must be True in prod (HTTPS)
        max_age=14400
    )
    db.add(AuditLog(user_id=user.id, action="LOGIN", target="SYSTEM"))
    db.commit()
    return {"message": "Logged in"}


@router.post("/logout")
async def logout(response: Response, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # AUDIT LOG: Record logout before clearing session cookies
    db.add(AuditLog(user_id=user.id, action="LOGOUT", target="SYSTEM"))
    db.commit()
    
    response.delete_cookie("access_token")
    return {"message": "Logged out"}

@router.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}

@router.post("/change-password")
async def change_password(data: PasswordChange, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if len(data.new_password) > 64:
        raise HTTPException(status_code=400, detail="Password too long (max 64 characters)")

    if not verify_password(data.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect old password")
        
    user.hashed_password = get_password_hash(data.new_password)
    db.add(AuditLog(user_id=user.id, action="CHANGED_PASSWORD", target="SELF"))
    db.commit()
    return {"message": "Password updated successfully"}