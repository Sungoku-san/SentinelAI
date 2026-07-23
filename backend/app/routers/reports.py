from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from backend.app.controllers.report_controller import report_controller_instance
from backend.app.middleware.auth_middleware import get_current_user

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/pdf")
async def download_pdf_report(username: str = Depends(get_current_user)):
    """Triggers and streams a detailed PDF executive report."""
    filepath = await report_controller_instance.get_pdf_report()
    return FileResponse(
        filepath,
        media_type="application/pdf",
        filename="sentinelai_threat_intelligence_report.pdf"
    )

@router.get("/csv")
async def download_csv_report(username: str = Depends(get_current_user)):
    """Triggers and streams a raw CSV file dump of captured attacker sessions."""
    filepath = await report_controller_instance.get_csv_report()
    return FileResponse(
        filepath,
        media_type="text/csv",
        filename="sentinelai_session_logs.csv"
    )
