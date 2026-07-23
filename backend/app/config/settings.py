import os
from pydantic_settings import BaseSettings
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

class Settings(BaseSettings):
    ENV: str = "development"
    
    # MongoDB
    MONGO_URI: str = "mongodb://localhost:27017"
    MONGO_DB_NAME: str = "sentinelai"
    
    # Auth
    JWT_SECRET: str = "super-secret-sentinelai-key-change-me"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "adminpassword123"
    
    # Port Settings
    PORT_SSH: int = 2222
    PORT_HTTP: int = 8080
    PORT_FTP: int = 2121
    PORT_TELNET: int = 2323
    
    # Adaptive Settings
    BRUTE_FORCE_THRESHOLD: int = 5
    TARPIT_LATENCY_MAX: float = 5.0
    FS_REALISM_LEVEL: int = 2
    
    # Notifications
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    ALERT_EMAIL_RECIPIENT: str = ""
    
    # Directories
    QUARANTINE_DIR: str = str(BASE_DIR / "backend" / "logs" / "quarantine")
    LOG_DIR: str = str(BASE_DIR / "backend" / "logs")
    REPORT_DIR: str = str(BASE_DIR / "backend" / "reports")
    MODEL_PATH: str = str(BASE_DIR / "backend" / "models" / "threat_model.joblib")

    class Config:
        env_file = str(BASE_DIR / ".env")
        env_file_encoding = "utf-8"
        extra = "ignore"

settings = Settings()

# Ensure directories exist
os.makedirs(settings.QUARANTINE_DIR, exist_ok=True)
os.makedirs(settings.LOG_DIR, exist_ok=True)
os.makedirs(settings.REPORT_DIR, exist_ok=True)
os.makedirs(os.path.dirname(settings.MODEL_PATH), exist_ok=True)
