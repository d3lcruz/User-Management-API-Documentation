from fastapi import APIRouter, status, HTTPException, Depends
from database.client import collection
from database.users import create_user, get_user, pwd_context
from database.schemas.users import user_serial
from models.users import User, UserCreate, UserDB 
from database.client import collection
from bson.objectid import ObjectId

router = APIRouter(prefix="/users", tags=["users"], responses={404:{"message":"No found"}})

@router.post("/register", response_model=User)
async def register(user: UserCreate):
    user_dict = user.dict(exclude_unset=True)
    try:
        existing_user = get_user(user_dict["username"])
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        create_user(user_dict)
    except:
        raise HTTPException(status_code=200, detail="Register User")
    return user

@router.post("/login", response_model=User)
async def login_user(username: str, password: str):
    login_user = get_user(username)
    if not login_user or not pwd_context.verify(password, login_user["hashed_password"]):
        return False
    else:
        return login_user
    

@router.put("/profile", response_model=User)
async def update_profile(user_id:str, user: User):
    user_dic = user.dict(exclude_unset=True)
    try:
        obj_id = ObjectId(user_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error id")
    
    new_user = collection.find_one_and_update({"_id":obj_id}, {"$set":user_dic})
    if new_user is None:
        raise HTTPException(status_code=500, detail="Error id")
    new_user["user_id"] = str(new_user["_id"])
    return User(**new_user) 