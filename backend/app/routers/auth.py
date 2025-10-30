from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os
from app.database import get_db
from app.models.security import User

router = APIRouter(prefix="/auth", tags=["auth"])

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.getenv("SECRET_KEY", "WPVFS-3jXj0t-MEW7r_lnJH02_4nN0UcrbFFFLBVxQ0")
ALGORITHM = "HS256"

class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str = None

class UserLogin(BaseModel):
    email: str
    password: str

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

@router.post("/register")
async def register(data: UserRegister, db: Session = Depends(get_db)):
    # Check if user exists
    existing_user = db.query(User).filter(User.email == data.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create new user
    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
        notification_email=data.email,  # Default to same email
        email_notifications_enabled=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Generate token
    token = jwt.encode({"sub": str(user.id), "email": user.email}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "user_id": user.id}

@router.post("/login")
async def login(data: UserLogin, db: Session = Depends(get_db)):
    # Find user
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Generate token
    token = jwt.encode({"sub": str(user.id), "email": user.email}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer", "user_id": user.id}