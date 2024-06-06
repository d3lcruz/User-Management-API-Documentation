from fastapi import Depends, APIRouter, status, HTTPException 
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Optional
from pydantic import BaseModel
from database.users import create_user, get_user, pwd_context, get_password_hash
from database.schemas.users import user_serial
from models.users import User, UserCreate, UserDB, PasswordResetRequest
from database.client import collection

SECRET_KEY = "$2y$10$Q3Gn7Q028NQzjeN5lbeGFOULv.eMKOZlSoJIwkGeqi8yCSjLGgvZW"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
TOKEN_EXPIRATION = timedelta(hours=24)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

router = APIRouter(tags=["token"])
    
class Token(BaseModel):
    access_token: str
    token_type: str

class Tokendata(BaseModel):
    username: Optional[str] = None

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not pwd_context.verify(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta]= None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutos=15)
    to_encode.update({"exp":expire})
    enconded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return enconded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = Tokendata(username=username)
    except JWTError:
        raise credentials_exception
    return get_user(username=token_data.username)

async def get_current_activate_user(current_user:dict = Depends(get_current_user)):
    if current_user.get("disable"):
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user 


@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/profile", response_model=User)
async def profile(token:str = Depends(oauth2_scheme)):
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = Tokendata(username=username)
    except JWTError:
        raise credentials_exception
    return get_user(username=token_data.username)


@router.post("/users/reset-password")
async def reset_password(req:PasswordResetRequest):
    user = collection.find_one({"email": req.email})
    if user is None:
        raise HTTPException(status_code=404, detail="Email not found")
    
    token_data = {"email": req.email, "exp": datetime.utcnow() + TOKEN_EXPIRATION}
    token = jwt.encode(token_data, SECRET_KEY)
    return token

@router.post("/users/reset-password/{token}", status_code=204)
async def reset_password_confirm(token: str, new_password: str):
    try:
        print("Received token:", token)
        # Decode token and verify expiration
        token_data = jwt.decode(token, SECRET_KEY)
        print("Decoded token data:", token_data)
        
        # Extract expiration time from token data
        expiration_timestamp = token_data["exp"]
        expiration_datetime = datetime.utcfromtimestamp(expiration_timestamp)
        
        # Check if the token has expired
        if datetime.utcnow() > expiration_datetime:
            raise HTTPException(status_code=400, detail="Token expired")
    except jwt.JWTError as e:
        print("Error decoding token:", e)
        raise HTTPException(status_code=400, detail="Invalid token")

    email = token_data["email"]
    user = collection.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=404, detail="Email not found")

    # Hash the new password
    hashed_password = get_password_hash(new_password)

    # Update password in the database
    collection.update_one({"email": email}, {"$set": {"hashed_password": hashed_password}})

@router.delete("/users/delete", status_code=204)
async def delete_user_account(current_user: dict = Depends(get_current_activate_user)): #
    collection.delete_one({"_id": current_user["_id"]})
