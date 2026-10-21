from pydantic import BaseModel, Field, field_validator
import re

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=256)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL_RE.match(value):
            raise ValueError("Invalid email address")
        return value

class RegisterRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=256)
    organization: str = Field(min_length=2, max_length=200)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL_RE.match(value):
            raise ValueError("Invalid email address")
        return value

class URLRequest(BaseModel):
    url: str = Field(min_length=8, max_length=2048)

class CaseRequest(BaseModel):
    title: str = Field(min_length=2, max_length=255)
    priority: str = "medium"
    notes: str = ""
