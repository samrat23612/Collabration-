# app.py
import asyncio
import datetime as dt
import secrets
from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlmodel import SQLModel, Field, Session, create_engine, select

# -----------------------------
# Config
# -----------------------------
JWT_SECRET = secrets.token_urlsafe(32)  # replace with env var in prod
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = "sqlite:///./collab.db"
engine = create_engine(DATABASE_URL, echo=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

app = FastAPI(title="Collab API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Models
# -----------------------------
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    name: str
    hashed_password: str
    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.utcnow())

class Room(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True)
    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.utcnow())

class Message(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    room_id: int = Field(index=True)
    user_id: int = Field(index=True)
    content: str
    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.utcnow())

class Task(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    room_id: int = Field(index=True)
    title: str
    description: Optional[str] = None
    status: str = Field(default="todo")  # todo, in_progress, done
    assignee_id: Optional[int] = Field(default=None)
    created_at: dt.datetime = Field(default_factory=lambda: dt.datetime.utcnow())

# -----------------------------
# Schemas
# -----------------------------
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[int] = None

class UserCreate(BaseModel):
    email: str
    name: str
    password: str

class UserRead(BaseModel):
    id: int
    email: str
    name: str

class RoomCreate(BaseModel):
    name: str

class MessageCreate(BaseModel):
    content: str

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    assignee_id: Optional[int] = None

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    assignee_id: Optional[int] = None

# -----------------------------
# Auth helpers
# -----------------------------
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

def get_db():
    with Session(engine) as session:
        yield session

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception
    user = db.get(User, token_data.user_id)
    if user is None:
        raise credentials_exception
    return user

# -----------------------------
# Startup
# -----------------------------
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)
    # Ensure a default room
    with Session(engine) as session:
        if not session.exec(select(Room).where(Room.name == "general")).first():
            session.add(Room(name="general"))
            session.commit()

# -----------------------------
# Auth routes
# -----------------------------
@app.post("/auth/signup", response_model=UserRead)
def signup(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.exec(select(User).where(User.email == payload.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=payload.email, name=payload.name, hashed_password=hash_password(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserRead(id=user.id, email=user.email, name=user.name)

@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.id})
    return Token(access_token=token, token_type="bearer")

# -----------------------------
# Rooms & messages
# -----------------------------
@app.post("/rooms", response_model=Room)
def create_room(payload: RoomCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if db.exec(select(Room).where(Room.name == payload.name)).first():
        raise HTTPException(status_code=400, detail="Room already exists")
    room = Room(name=payload.name)
    db.add(room)
    db.commit()
    db.refresh(room)
    return room

@app.get("/rooms", response_model=List[Room])
def list_rooms(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.exec(select(Room)).all()

@app.get("/rooms/{room_id}/messages", response_model=List[Message])
def get_messages(room_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.exec(select(Message).where(Message.room_id == room_id).order_by(Message.created_at)).all()

# -----------------------------
# Tasks
# -----------------------------
@app.post("/rooms/{room_id}/tasks", response_model=Task)
def create_task(room_id: int, payload: TaskCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    room = db.get(Room, room_id)
    if not room:
        raise HTTPException(status_code=404, detail="Room not found")
    task = Task(room_id=room_id, title=payload.title, description=payload.description, assignee_id=payload.assignee_id)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task

@app.get("/rooms/{room_id}/tasks", response_model=List[Task])
def list_tasks(room_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.exec(select(Task).where(Task.room_id == room_id).order_by(Task.created_at)).all()

@app.patch("/tasks/{task_id}", response_model=Task)
def update_task(task_id: int, payload: TaskUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    update_fields = payload.dict(exclude_unset=True)
    for k, v in update_fields.items():
        setattr(task, k, v)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task

# -----------------------------
# Real-time: WebSocket manager
# -----------------------------
class ConnectionManager:
    def __init__(self):
        self.active_rooms: Dict[int, List[WebSocket]] = {}

    async def connect(self, room_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_rooms.setdefault(room_id, []).append(websocket)

    def disconnect(self, room_id: int, websocket: WebSocket):
        if room_id in self.active_rooms and websocket in self.active_rooms[room_id]:
            self.active_rooms[room_id].remove(websocket)

    async def broadcast(self, room_id: int, message: dict):
        for ws in list(self.active_rooms.get(room_id, [])):
            try:
                await ws.send_json(message)
            except Exception:
                # Drop bad connections
                self.disconnect(room_id, ws)

manager = ConnectionManager()

@app.websocket("/ws/rooms/{room_id}")
async def websocket_endpoint(websocket: WebSocket, room_id: int, token: Optional[str] = None):
    # Lightweight token check without FastAPI dependency in ws
    if not token:
        await websocket.close(code=4401)  # unauthorized
        return
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id = payload.get("sub")
        if not user_id:
            await websocket.close(code=4401)
            return
    except JWTError:
        await websocket.close(code=4401)
        return

    await manager.connect(room_id, websocket)
    await manager.broadcast(room_id, {"type": "presence", "user_id": user_id, "status": "joined"})
    try:
        while True:
            data = await websocket.receive_json()
            # Expect: {"type": "message", "content": "Hello"}
            if data.get("type") == "message":
                content = str(data.get("content", "")).strip()
                if not content:
                    continue
                # Persist message
                with Session(engine) as db:
                    msg = Message(room_id=room_id, user_id=user_id, content=content)
                    db.add(msg)
                    db.commit()
                    db.refresh(msg)
                    payload_out = {
                        "type": "message",
                        "id": msg.id,
                        "room_id": room_id,
                        "user_id": user_id,
                        "content": msg.content,
                        "created_at": msg.created_at.isoformat() + "Z",
                    }
                    await manager.broadcast(room_id, payload_out)
            elif data.get("type") == "typing":
                await manager.broadcast(room_id, {"type": "typing", "user_id": user_id})
            await asyncio.sleep(0)  # yield
    except WebSocketDisconnect:
        manager.disconnect(room_id, websocket)
        await manager.broadcast(room_id, {"type": "presence", "user_id": user_id, "status": "left"})
