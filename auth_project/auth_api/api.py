from django.contrib.auth import get_user_model, authenticate
from ninja import NinjaAPI
from ninja.security import HttpBearer
from .schemas import UserIn, UserOut, TokenOut
from django.contrib.auth.hashers import make_password
from jose import jwt
from datetime import datetime, timedelta

api = NinjaAPI()
User = get_user_model()

SECRET_KEY = "qttmbIPcNBIDLXuhuWAhUl5x9jSnuzYf" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class AuthBearer(HttpBearer):
    def authenticate(self, request, token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                return None
        except jwt.JWTError:
            return None
        user = User.objects.filter(username=username).first()
        if user is None:
            return None
        return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@api.post("/register", response=UserOut)
def register(request, user_in: UserIn):
    user = User.objects.create(
        username=user_in.username,
        email=user_in.email,
        password=make_password(user_in.password)
    )
    return user

@api.post("/login", response=TokenOut)
def login(request, username: str, password: str):
    user = authenticate(username=username, password=password)
    if user is None:
        return api.create_response(request, {"detail": "Invalid credentials"}, status=401)
    token = create_access_token({"sub": user.username})
    return {"access_token": token}

@api.get("/me", response=UserOut, auth=AuthBearer())
def me(request):
    return request.auth
