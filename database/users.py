from passlib.context import CryptContext
from database.client import collection

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user(username: str):
    return collection.find_one({"username": username})

def create_user(user):
    user["hashed_password"] = pwd_context.hash(user["password"])
    del user["password"]
    collection.insert_one(user)
    return user

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)