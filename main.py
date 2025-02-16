from fastapi import FastAPI, HTTPException, Body, Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext

app = FastAPI()
SECRET_KEY = "hungkien"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
fake_users_db = {
    "admin": {
        "username": "admin",
        "full_name": "Admin",
        "email": "admin@gmail.com",
        "hashed_password": pwd_context.hash("password"),
    }
}
class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
items = []
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise HTTPException(status_code=401, detail="Invalid token")
        return fake_users_db[username]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
@app.post("/login", response_model=TokenResponse)
def login(request: LoginRequest):
    user = fake_users_db.get(request.username)
    if not user or not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token = create_access_token(data={"sub": request.username}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": access_token, "token_type": "bearer"}
@app.post("/items")
def create_item(item: str, current_user: dict = Depends(get_current_user)):  
    new_item = {
        "id": len(items) + 1,
        "name": item
    }
    items.append(new_item)
    return {"message": "Item added", "item": new_item}
@app.post("/itemss")
def create_item(item: str = Body(..., embed=True), current_user: str = Depends(get_current_user)):  
    new_item = {
        "id": len(items) + 1,
        "name": item,
    }
    items.append(new_item)
    return {"message": "Item added", "item": new_item}
@app.get("/items/{item_id}")
def read_item(item_id: int, current_user: dict = Depends(get_current_user)):
    if item_id > len(items) or item_id < 1:
        raise HTTPException(status_code=404, detail=f"Item {item_id} not found")
    return items[item_id-1]


