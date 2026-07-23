from fastapi import APIRouter, Depends
from backend.app.controllers.auth_controller import auth_controller_instance
from backend.app.middleware.auth_middleware import get_current_user
from backend.app.models.schemas import LoginRequest, TokenResponse, UserProfileResponse

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest):
    """Admin Login Endpoint. Validates and returns JWT token."""
    return await auth_controller_instance.login(payload)

@router.get("/me", response_model=UserProfileResponse)
async def user_profile(username: str = Depends(get_current_user)):
    """Retrieves authenticated admin username."""
    return UserProfileResponse(username=username)
