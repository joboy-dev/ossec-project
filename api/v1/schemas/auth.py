from enum import Enum
from typing import Any, Optional
from xxlimited import Str
from pydantic import BaseModel, EmailStr
import datetime as dt
from api.v1.models.user import User


class CreateUser(BaseModel):
    
    username: str
    email: EmailStr
    password: str
    confirm_password: str
    

class LoginSchema(BaseModel):
    
    username: str
    password: str
    

class MagicLoginRequest(BaseModel):
    
    email: EmailStr
    
    
class ResetPasswordRequest(BaseModel):
    email: EmailStr


class ResetPassword(BaseModel):
    password: str

    
class GoogleAuth(BaseModel):
    id_token: str
    