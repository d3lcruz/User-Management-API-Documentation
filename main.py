from fastapi import FastAPI, Depends
from routers import auth
from routers import users   
from routers.auth import get_current_user
from models.users import User

app = FastAPI()
app.include_router(auth.router)
app.include_router(users.router)

@app.get("/")
async def home(current_user: User = Depends(get_current_user)):
    return {f"Message":"Welcome to the Book Management API{current_user}"}

#pip install fastapi uvicorn pymongo python-jose python-multipart passlib