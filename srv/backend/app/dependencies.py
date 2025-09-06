from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from . import models, crud

def get_db():
    db = models.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(request: Request, db: Session = Depends(get_db)):
    username = request.cookies.get("session_id")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")
    return user

def get_current_admin(request: Request, db: Session = Depends(get_db)):
    username = request.cookies.get("admin_session_id")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated as admin",
            headers={"WWW-Authenticate": "Bearer"},
        )
    admin = crud.get_admin_by_username(db, username=username)
    if admin is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin user")
    return admin
