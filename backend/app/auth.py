from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
import os

security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY", "WPVFS-3jXj0t-MEW7r_lnJH02_4nN0UcrbFFFLBVxQ0")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """
    Simple auth - validates JWT token
    """
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"id": user_id, "email": payload.get("email")}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")