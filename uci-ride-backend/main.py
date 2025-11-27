from datetime import datetime, timedelta
from typing import Dict, Optional, List

from fastapi import FastAPI, HTTPException, Header, Depends, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
import hashlib

app = FastAPI(title="UCI Carpool Backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 开发阶段先全放开，上线再收紧
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= 安全相关设置 =========
SECRET_KEY = "CHANGE_THIS_TO_SOMETHING_RANDOM_AND_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 天

# ========= 简单“假数据库”（内存） =========
fake_users_db: Dict[str, Dict] = {}  # key = email
next_user_id = 1

fake_rides_db: Dict[int, Dict] = {}  # key = ride id
next_ride_id = 1


# ========= Pydantic 模型 =========
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    name: str
    email: EmailStr


class Token(BaseModel):
    access_token: str
    token_type: str


class LoginInput(BaseModel):
    email: EmailStr
    password: str


class RideCreate(BaseModel):
    from_location: str
    to_location: str
    departure_time: datetime
    total_seats: int
    remaining_seats: int
    gender_preference: str = "any"  # "any" / "female_only" / "male_only"
    price_per_person: Optional[float] = None
    contact_wechat: str
    notes: Optional[str] = None


class RideOut(BaseModel):
    id: int
    user_id: int
    from_location: str
    to_location: str
    departure_time: datetime
    total_seats: int
    remaining_seats: int
    gender_preference: str
    price_per_person: Optional[float]
    contact_wechat: str
    notes: Optional[str]
    status: str  # "open" / "closed"


# ========= 工具函数 =========
def hash_password(password: str) -> str:
    """用 SHA256 简单加密一下密码。"""
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_user_by_email(email: str) -> Optional[Dict]:
    return fake_users_db.get(email.lower())


def get_current_user(
    authorization: Optional[str] = Header(None),
    token: Optional[str] = Query(None),
) -> Dict:
    """
    优先从 Authorization: Bearer <token> 里拿，
    如果没有，再从 URL 的 ?token= 里拿。
    """
    raw_token: Optional[str] = None

    # 1. Header 里的 Bearer token
    if authorization and authorization.startswith("Bearer "):
        raw_token = authorization.split(" ", 1)[1].strip()
    # 2. 否则用 ?token=
    elif token:
        raw_token = token

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header or token query parameter missing",
        )

    try:
        payload = jwt.decode(raw_token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token payload",
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate token",
        )

    user = get_user_by_email(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


# ========= 路由 =========
@app.get("/")
def read_root():
    return {"message": "UCI Carpool backend is running with simple auth!"}


@app.post("/auth/register", response_model=UserOut)
def register(user_in: UserCreate):
    """
    注册新用户。要求必须 @uci.edu 邮箱。
    """
    global next_user_id

    email = user_in.email.lower()
    if not email.endswith("@uci.edu"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email must be a UCI email address (@uci.edu).",
        )

    if get_user_by_email(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered.",
        )

    hashed = hash_password(user_in.password)

    user_record = {
        "id": next_user_id,
        "name": user_in.name,
        "email": email,
        "hashed_password": hashed,
    }
    fake_users_db[email] = user_record
    next_user_id += 1

    return UserOut(id=user_record["id"], name=user_record["name"], email=user_record["email"])


@app.post("/auth/login", response_model=Token)
def login(data: LoginInput):
    """
    邮箱 + 密码登录，返回 access_token
    """
    email = data.email.lower()
    user = get_user_by_email(email)
    if not user or not verify_password(data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
        )

    access_token = create_access_token(data={"sub": user["email"]})
    return Token(access_token=access_token, token_type="bearer")


@app.get("/auth/me", response_model=UserOut)
def read_me(current_user: Dict = Depends(get_current_user)):
    """
    获取当前登录用户信息
    """
    return UserOut(
        id=current_user["id"],
        name=current_user["name"],
        email=current_user["email"],
    )


@app.post("/rides", response_model=RideOut)
def create_ride(ride_in: RideCreate, current_user: Dict = Depends(get_current_user)):
    """
    创建一条拼车单（需要登录）
    """
    global next_ride_id

    ride = {
        "id": next_ride_id,
        "user_id": current_user["id"],
        "from_location": ride_in.from_location,
        "to_location": ride_in.to_location,
        "departure_time": ride_in.departure_time,
        "total_seats": ride_in.total_seats,
        "remaining_seats": ride_in.remaining_seats,
        "gender_preference": ride_in.gender_preference,
        "price_per_person": ride_in.price_per_person,
        "contact_wechat": ride_in.contact_wechat,
        "notes": ride_in.notes,
        "status": "open",
    }
    fake_rides_db[next_ride_id] = ride
    next_ride_id += 1
    return RideOut(**ride)


@app.get("/rides", response_model=List[RideOut])
def list_rides(
    from_location: Optional[str] = None,
    to_location: Optional[str] = None,
):
    """
    列出所有开放拼车单，可按出发地/目的地筛选
    """
    results: List[RideOut] = []
    for ride in fake_rides_db.values():
        if ride["status"] != "open":
            continue
        if from_location and from_location.lower() not in ride["from_location"].lower():
            continue
        if to_location and to_location.lower() not in ride["to_location"].lower():
            continue
        results.append(RideOut(**ride))
    return results


@app.get("/rides/{ride_id}", response_model=RideOut)
def get_ride(ride_id: int):
    """
    查看某条拼车详情
    """
    ride = fake_rides_db.get(ride_id)
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")
    return RideOut(**ride)


@app.post("/rides/{ride_id}/decrease_seat", response_model=RideOut)
def decrease_seat(ride_id: int, current_user: Dict = Depends(get_current_user)):
    """
    发帖人减少一个座位；减到 0 自动 closed
    """
    ride = fake_rides_db.get(ride_id)
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")

    if ride["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed to modify this ride")

    if ride["status"] != "open":
        raise HTTPException(status_code=400, detail="Ride is not open")

    if ride["remaining_seats"] > 0:
        ride["remaining_seats"] -= 1
        if ride["remaining_seats"] == 0:
            ride["status"] = "closed"

    return RideOut(**ride)


@app.post("/rides/{ride_id}/close", response_model=RideOut)
def close_ride(ride_id: int, current_user: Dict = Depends(get_current_user)):
    """
    发帖人手动关闭拼车单
    """
    ride = fake_rides_db.get(ride_id)
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")

    if ride["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Not allowed to modify this ride")

    ride["status"] = "closed"
    return RideOut(**ride)
