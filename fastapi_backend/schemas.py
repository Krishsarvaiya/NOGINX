from pydantic import BaseModel, EmailStr, Field


class SignupRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str


class Features(BaseModel):
    features: list[dict[str, int]]


class Feature(BaseModel):
    feature: dict[str, int]


class UserProfile(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        from_attributes = True
