from typing import Optional, Annotated
from pydantic import BaseModel, EmailStr, StringConstraints, Field
from enum import Enum

class TodoStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"

class TodoCreate(BaseModel):
    task: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    status: TodoStatus

class TodoUpdate(BaseModel):
    task: Optional[Annotated[str, StringConstraints(min_length=1, max_length=500)]] = None
    status: Optional[TodoStatus] = None

class UserRegister(BaseModel):
    email: EmailStr
    password: Annotated[str, StringConstraints(min_length=8, max_length=50)]
    username: Annotated[str, StringConstraints(min_length=3, max_length=50)]

class UserLogin(BaseModel):
    email: EmailStr
    password: str

