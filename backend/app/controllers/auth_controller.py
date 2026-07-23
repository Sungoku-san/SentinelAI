from fastapi import HTTPException, status
from backend.app.config.settings import settings
from backend.app.utils.crypto import create_access_token
from backend.app.models.schemas import LoginRequest, TokenResponse

class AuthController:
    async def login(self, payload: LoginRequest) -> TokenResponse:
        """Authenticates admin and returns JWT token."""
        # Check against environment variables
        if payload.username == settings.ADMIN_USERNAME and payload.password == settings.ADMIN_PASSWORD:
            access_token = create_access_token(data={"sub": payload.username})
            return TokenResponse(access_token=access_token, token_type="bearer")
            
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

auth_controller_instance = AuthController()
