from fastapi import APIRouter, Depends
from backend.app.controllers.dashboard_controller import dashboard_controller_instance
from backend.app.middleware.auth_middleware import get_current_user
from backend.app.models.schemas import DashboardStatsResponse, SystemStatusResponse

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStatsResponse)
async def dashboard_stats(username: str = Depends(get_current_user)):
    """Retrieves aggregated metrics, classifications, and top attacking hosts."""
    return await dashboard_controller_instance.get_dashboard_stats()

@router.get("/status", response_model=SystemStatusResponse)
async def system_status(username: str = Depends(get_current_user)):
    """Retrieves port availability, emulator running statuses, and sniffer packet flows."""
    return dashboard_controller_instance.get_system_status()
