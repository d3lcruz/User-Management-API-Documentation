from pydantic import BaseModel, EmailStr 
from typing import Optional

class User(BaseModel):
    username: str
    email: EmailStr
    fullname: Optional[str] = None
    disable: Optional[bool] = None 

class PasswordResetRequest(BaseModel):
    email: str
    
class UserDB(User):
    hashed_password: str
    
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    fullname: Optional[str] = None
    password: str