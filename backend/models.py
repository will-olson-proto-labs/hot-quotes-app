from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

# User models
class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    role: str

class UserLogin(BaseModel):
    username: str
    password: str

class SelfRegister(BaseModel):
    email: str
    password: str
    role: str  # Added role field for user choice

class UserUpdate(BaseModel):
    role: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# Quote models
class QuoteCreate(BaseModel):
    quote_number: str
    reason_for_hot: str
    reason_other_text: Optional[str] = None
    additional_info: str
    special_process: str
    subject_line: Optional[str] = None
    additional_cc_emails: Optional[List[str]] = []
    priority: Optional[str] = "normal"

class QuoteResponse(BaseModel):
    id: int
    quote_number: str
    reason_for_hot: str
    reason_other_text: Optional[str]
    additional_info: str
    special_process: str
    subject_line: Optional[str]
    additional_cc_emails: Optional[str]  # JSON string in database
    file_path: Optional[str]
    original_filename: Optional[str]
    status: str
    priority: str
    submitted_by: str
    claimed_by: Optional[str]
    created_at: datetime
    claimed_at: Optional[datetime]
    completed_at: Optional[datetime]
    notes: Optional[str]

    class Config:
        from_attributes = True

class QuoteUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None