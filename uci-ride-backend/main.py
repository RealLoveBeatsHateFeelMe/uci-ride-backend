from datetime import datetime, timedelta, date, time
from typing import Dict, Optional, List

from fastapi import FastAPI, HTTPException, Header, Depends, status, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
import hashlib

app = FastAPI(title="UCI Carpool Backend")

# ✅ 正确的 CORS 写法
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 开发阶段先全放开，上线再收紧
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========= 安全相关设置 =========
SECRET_KEY = "RealLoveBeatsHateFeelMe11/28DayInTheLife"
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

    # ---- 时间相关字段 ----
    # departure_time 先按 str 接收，兼容：
    # 1）旧前端：完整 datetime 字符串
    # 2）新前端：纯时间 "HH:MM"
    # 3）用户没填：可能是 "" 或根本不带这个字段
    departure_time: Optional[str] = None
    # 只日期（可选）：支持“仅日期”
    departure_date: Optional[date] = None
    # 时段（可选）：morning/noon/afternoon/evening
    time_slot: Optional[str] = None

    total_seats: int
    remaining_seats: int
    gender_preference: str = "any"  # "any" / "female_only" / "male_only"
    contact_wechat: str
    notes: Optional[str] = None


class RideOut(BaseModel):
    id: int
    user_id: int
    from_location: str
    to_location: str

    # 对前端暴露的新结构：日期 + 时段 + 具体时间
    departure_date: Optional[date]
    time_slot: Optional[str]
    departure_time: Optional[time]

    total_seats: int
    remaining_seats: int
    gender_preference: str
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


# -------- Auth --------
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


# -------- Rides: 创建 --------
@app.post("/rides", response_model=RideOut)
def create_ride(ride_in: RideCreate, current_user: Dict = Depends(get_current_user)):
    """
    创建一条拼车单（需要登录）

    时间兼容策略：
    - 如果前端只传了 departure_time = datetime 字符串（老版本行为）：
        * 如果没有单独传 departure_date，就从 datetime 里自动拆出日期
        * 再从 datetime 里拆出具体时间（HH:MM:SS）
    - 如果前端传的是新的字段：
        * departure_date / time_slot / departure_time（"HH:MM"）直接使用
    - 如果 departure_time 是空字符串 ""，当作没填
    """
    global next_ride_id

    # 归一化日期和时间
    normalized_date: Optional[date] = ride_in.departure_date
    normalized_time: Optional[time] = None

    raw_time = ride_in.departure_time

    # 1. 如果是空字符串或者 None，就当没填
    if raw_time is None or str(raw_time).strip() == "":
        pass  # 保持 normalized_time = None
    else:
        time_str = str(raw_time).strip()
        parsed = False

        # 2. 先尝试按完整 datetime 解析（兼容老前端可能传的 datetime）
        try:
            # 兼容末尾带 "Z" 的情况
            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            if normalized_date is None:
                normalized_date = dt.date()
            normalized_time = dt.time()
            parsed = True
        except Exception:
            parsed = False

        # 3. 如果不是 datetime，再尝试当纯时间 "HH:MM" 解析
        if not parsed:
            try:
                normalized_time = time.fromisoformat(time_str)
                parsed = True
            except Exception:
                parsed = False

        # 4. 两种都解析不了，就报一个可读的错误
        if not parsed:
            raise HTTPException(
                status_code=400,
                detail="Invalid departure_time format. Use HH:MM or an ISO datetime string.",
            )

    ride = {
        "id": next_ride_id,
        "user_id": current_user["id"],
        "from_location": ride_in.from_location,
        "to_location": ride_in.to_location,
        "departure_date": normalized_date,
        "time_slot": ride_in.time_slot,
        "departure_time": normalized_time,
        "total_seats": ride_in.total_seats,
        "remaining_seats": ride_in.remaining_seats,
        "gender_preference": ride_in.gender_preference,
        "contact_wechat": ride_in.contact_wechat,
        "notes": ride_in.notes,
        "status": "open",
    }
    fake_rides_db[next_ride_id] = ride
    next_ride_id += 1
    return RideOut(**ride)


# ---- 辅助函数：用于排序 / 过滤时间 ----
def _ride_datetime(ride: Dict) -> Optional[datetime]:
    d = ride.get("departure_date")
    t = ride.get("departure_time")
    if d is None:
        return None
    if t is None:
        t = time(0, 0)  # 如果没具体时间，就当成当天 00:00
    return datetime.combine(d, t)


# -------- Rides: 列表 --------
@app.get("/rides", response_model=List[RideOut])
def list_rides(
    from_location: Optional[str] = None,
    to_location: Optional[str] = None,
    departure_date: Optional[date] = None,  # 搜索开始日期：这一天及之后
    time_slot: Optional[str] = None,        # 'morning' | 'noon' | 'afternoon' | 'evening'
):
    """
    列出所有开放拼车单：

    - 只显示 status = open 的单
    - 自动过滤掉已经过期 3 小时以上的单
    - 如果传了 departure_date：显示“这一天及之后”的所有单
    - 如果传了 time_slot：只留下对应时段的单
    - 最后按出发时间从近到远排序
    """
    now = datetime.utcnow()
    results: List[Dict] = []

    for ride in fake_rides_db.values():
        if ride["status"] != "open":
            continue

        ride_dt = _ride_datetime(ride)

        # ① 自动过滤掉已经过去 3 小时的单
        if ride_dt is not None and ride_dt < now - timedelta(hours=3):
            continue

        # ② 出发地 / 目的地 关键字过滤
        if from_location and from_location.lower() not in ride["from_location"].lower():
            continue
        if to_location and to_location.lower() not in ride["to_location"].lower():
            continue

        # ③ 如果用户在前端选了“出发日期”，只保留 >= 该日期的单
        if departure_date:
            min_dt = datetime.combine(departure_date, time(0, 0))  # 选中那天的 00:00
            if ride_dt is None or ride_dt < min_dt:
                continue

        # ④ 时段过滤（早上/中午/下午/晚上）
        if time_slot and ride.get("time_slot") != time_slot:
            continue

        results.append(ride)

    # ⑤ 按出发时间从近到远排序：
    #    有具体时间的排前面；没时间/没日期的放最后
    results.sort(key=lambda r: _ride_datetime(r) or datetime.max)

    return [RideOut(**r) for r in results]


# -------- Rides: 详情 --------
@app.get("/rides/{ride_id}", response_model=RideOut)
def get_ride(ride_id: int):
    """
    查看某条拼车详情
    """
    ride = fake_rides_db.get(ride_id)
    if not ride:
        raise HTTPException(status_code=404, detail="Ride not found")
    return RideOut(**ride)


# -------- Rides: 改座位 --------
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


# -------- Rides: 手动关闭 --------
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
