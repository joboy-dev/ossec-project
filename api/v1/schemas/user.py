from typing import Optional
from pydantic import BaseModel, EmailStr
import datetime as dt

    
class UpdateUser(BaseModel):
    
    username: Optional[str] = None
    password: Optional[str] = None
    old_password: Optional[str] = None
    
    
class AccountReactivationRequest(BaseModel):
    
    email: EmailStr
