from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from jose import jwt, JWTError
from app.core.database import get_db
from app.core.security import SECRET_KEY, ALGORITHM
from app.models.database import User

def get_token_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    # Remove 'Bearer ' prefix
    return token.replace("Bearer ", "")

def get_current_user(token: str = Depends(get_token_from_cookie), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid auth credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid auth credentials")
        
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user

def require_admin(current_user: User = Depends(get_current_user)):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user

def require_admin_or_analyst(current_user: User = Depends(get_current_user)):
    if current_user.role not in ["ADMIN", "ANALYST"]:
        raise HTTPException(status_code=403, detail="Insufficient privileges")
    return current_user