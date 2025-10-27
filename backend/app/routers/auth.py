from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import os

from app.database import get_db

router = APIRouter(prefix="/auth", tags=["auth"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY", "WPVFS-3jXj0t-MEW7r_lnJH02_4nN0UcrbFFFLBVxQ0")
ALGORITHM = "HS256"

class UserRegister(BaseModel):
    email: str
    password: str
    organization_name: str

class UserLogin(BaseModel):
    email: str
    password: str

@router.post("/register")
async def register(data: UserRegister, db: Session = Depends(get_db)):
    # Simple registration - just return success
    token = jwt.encode({"sub": "1", "email": data.email}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/login")
async def login(data: UserLogin, db: Session = Depends(get_db)):
    # Simple login - accept any credentials for now
    token = jwt.encode({"sub": "1", "email": data.email}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token, "token_type": "bearer"}