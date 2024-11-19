from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import Form
from fastapi.middleware.cors import CORSMiddleware
from schemas import UserResponse, UserRegister
from auth import hash_password, verify_password, create_token, get_current_user


app = FastAPI(title="User Registration and Login System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users_db = {}

@app.post("/register", response_model=UserResponse)
async def register(user_data: UserRegister):
    """Register a new user"""
    if user_data.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    

    hashed_password = hash_password(user_data.password)
    users_db[user_data.username] = {"username": user_data.username,"email": user_data.email,"password": hashed_password}
    return {"username": user_data.username,"email": user_data.email} 

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login a user"""
    user = users_db.get(form_data.username)
    
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    if not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    # Create access token
    token = create_token(form_data.username)
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/profile", response_model=UserResponse)
async def get_profile(username: str = Depends(get_current_user)):
    """Get user profile (protected route - requires token)"""
    user = users_db.get(username)
    if not user: 
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"username": user["username"], "email": user["email"]}