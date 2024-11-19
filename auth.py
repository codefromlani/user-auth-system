from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
import os 
from dotenv import load_dotenv


load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain_password: str) -> str:
    """Generate a hashed password using bycrpt"""
    return pwd_context.hash(plain_password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Check if the plain password matches the hashed password"""
    return pwd_context.verify(plain_password, hashed_password)

def create_token(username: str) -> str:
    """Create a JWT token for the user"""
    expiration = datetime.utcnow() + timedelta(minutes=30)

    # Create token data
    token_data = {"sub": username, "exp": expiration}

    # Create and return the token
    return jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Verify token and return current user"""
    try:
        # Decode the token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")

        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.PyJWKError:
        raise HTTPException(status_code=401, detail="Could not verify token")