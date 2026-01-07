"""Authentication endpoints."""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

router = APIRouter(tags=["auth"])

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    """User login endpoint."""
    # TODO: Implement actual authentication
    return {"access_token": "token", "token_type": "bearer"}
