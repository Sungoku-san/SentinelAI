import datetime
from fastapi import HTTPException
from backend.app.database.mongodb import get_database
from backend.app.services.report_generator import report_generator_instance

class ReportController:
    async def get_pdf_report(self) -> str:
        """Queries database sessions, builds PDF report, and returns local file path."""
        db = get_database()
        if db is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
            
        try:
            # Query sessions, sorted by threat score descending
            cursor = db.sessions.find({}).sort("threat_score", -1).limit(100)
            sessions = await cursor.to_list(length=100)
            
            if not sessions:
                raise HTTPException(status_code=404, detail="No threat sessions found to compile report.")
                
            filename = f"sentinelai_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            pdf_path = report_generator_instance.generate_pdf_report(sessions, filename)
            return pdf_path
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")

    async def get_csv_report(self) -> str:
        """Queries database sessions, builds CSV report, and returns local file path."""
        db = get_database()
        if db is None:
            raise HTTPException(status_code=500, detail="Database unavailable")
            
        try:
            cursor = db.sessions.find({}).sort("start_time", -1)
            sessions = await cursor.to_list(length=1000)
            
            if not sessions:
                raise HTTPException(status_code=404, detail="No threat sessions found to compile report.")
                
            filename = f"sentinelai_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            csv_path = report_generator_instance.generate_csv_report(sessions, filename)
            return csv_path
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to generate CSV: {str(e)}")

report_controller_instance = ReportController()
