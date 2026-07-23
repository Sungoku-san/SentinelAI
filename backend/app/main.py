from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from backend.app.config.settings import settings
from backend.app.database.mongodb import connect_to_mongo, close_mongo_connection
from backend.app.routers import auth, dashboard, sessions, reports
from backend.app.services.telnet_emulator import telnet_emulator_instance
from backend.app.services.ftp_emulator import ftp_emulator_instance
from backend.app.services.http_emulator import http_emulator_instance
from backend.app.services.ssh_emulator import ssh_emulator_instance
from backend.app.services.packet_analyzer import packet_analyzer_instance
from backend.app.utils.helpers import get_logger

logger = get_logger("main")

app = FastAPI(
    title="SentinelAI - AI Honeypot Administration API",
    description="Backend interface managing AI classifiers, session listeners, and dynamic honeypot tarpits.",
    version="1.0.0"
)

# Enable CORS for frontend dashboard interactions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all sources for local development/testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Register routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(sessions.router)
app.include_router(reports.router)

# Mount frontend production assets
dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(dist_dir):
    logger.info(f"Serving frontend static files from: {dist_dir}")
    app.mount("/assets", StaticFiles(directory=os.path.join(dist_dir, "assets")), name="assets")

    # Serve index.html for index or any non-API fallback routes
    @app.get("/{catchall:path}")
    async def serve_frontend(catchall: str):
        if catchall.startswith("api"):
            # Avoid trapping API routes
            return None
        return FileResponse(os.path.join(dist_dir, "index.html"))
else:
    logger.warning(f"Frontend dist folder not found at {dist_dir}. Serving API only.")


@app.on_event("startup")
async def startup_event():
    # Save running event loop for Paramiko thread access
    from backend.app.utils import helpers
    helpers.main_loop = asyncio.get_running_loop()
    
    logger.info("Initializing SentinelAI system services...")
    
    # 1. Connect to MongoDB
    try:
        await connect_to_mongo()
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}. Running in memory/log mode.")
        
    # 2. Start Packet Analyzer
    packet_analyzer_instance.start_capture()
    
    # 3. Start Honeypot Emulators
    try:
        await telnet_emulator_instance.start()
    except Exception as e:
        logger.error(f"Failed to start Telnet emulator: {e}")
        
    try:
        await ftp_emulator_instance.start()
    except Exception as e:
        logger.error(f"Failed to start FTP emulator: {e}")
        
    try:
        await http_emulator_instance.start()
    except Exception as e:
        logger.error(f"Failed to start HTTP emulator: {e}")
        
    try:
        await ssh_emulator_instance.start()
    except Exception as e:
        logger.error(f"Failed to start SSH emulator: {e}")
        
    logger.info("SentinelAI services initialized successfully.")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down SentinelAI system services...")
    
    # Stop Emulators
    try:
        await telnet_emulator_instance.stop()
    except Exception as e:
        logger.warning(f"Error stopping Telnet: {e}")
        
    try:
        await ftp_emulator_instance.stop()
    except Exception as e:
        logger.warning(f"Error stopping FTP: {e}")
        
    try:
        await http_emulator_instance.stop()
    except Exception as e:
        logger.warning(f"Error stopping HTTP: {e}")
        
    try:
        await ssh_emulator_instance.stop()
    except Exception as e:
        logger.warning(f"Error stopping SSH: {e}")
        
    # Stop Sniffer
    packet_analyzer_instance.stop_capture()
    
    # Close MongoDB Connection
    await close_mongo_connection()
    logger.info("SentinelAI shutdown sequence complete.")
