from pydantic import BaseModel, EmailStr, constr
from enum import Enum
from typing import Optional

class TodoStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"

class TodoCreate(BaseModel):
    task: constr(min_length=1, max_length=500)
    status: TodoStatus

class TodoUpdate(BaseModel):
    task: Optional[constr(min_length=1, max_length=500)] = None
    status: Optional[TodoStatus] = None

class UserRegister(BaseModel):
    email: EmailStr
    password: constr(min_length=8, max_length=50) 
    username: constr(min_length=3, max_length=50)

class UserLogin(BaseModel):
    email: EmailStr
    password: str
