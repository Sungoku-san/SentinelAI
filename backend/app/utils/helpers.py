import logging
import os
import hashlib
import httpx
from logging.handlers import RotatingFileHandler
from backend.app.config.settings import settings

def get_logger(name: str) -> logging.Logger:
    """Sets up a rotating file logger and console logger."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers if already configured
    if not logger.handlers:
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s [%(name)s:%(lineNo)d] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Adjust log format to capture line numbers (Note: standard python logRecord uses lineno, lowercase)
        formatter.default_msec_format = '%s.%03d'
        
        # Rotating File Handler
        log_file = os.path.join(settings.LOG_DIR, "sentinelai.log")
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        file_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s'))
        file_handler.setLevel(logging.INFO)
        
        # Stream Handler (Console)
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s'))
        stream_handler.setLevel(logging.INFO)
        
        logger.addHandler(file_handler)
        logger.addHandler(stream_handler)
        
    return logger

def get_file_hash(filepath: str) -> dict:
    """Calculates MD5 and SHA256 hashes of a file."""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    except Exception as e:
        # Fallback if file doesn't exist
        return {"md5": "", "sha256": "", "error": str(e)}

async def get_ip_details(ip: str) -> dict:
    """Looks up IP location using ip-api.com, falling back gracefully."""
    # Private IPs fallback
    private_prefixes = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
                        "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", 
                        "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.", "127.0.0.1")
    if ip.startswith(private_prefixes) or ip == "::1" or ip == "localhost":
        return {
            "country": "Local Network",
            "countryCode": "LOCAL",
            "region": "Intranet",
            "city": "Private IP",
            "lat": 0.0,
            "lon": 0.0,
            "isp": "Local Loopback/LAN"
        }
        
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"http://ip-api.com/json/{ip}")
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Unknown"),
                        "countryCode": data.get("countryCode", "UN"),
                        "region": data.get("regionName", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "isp": data.get("isp", "Unknown")
                    }
    except Exception:
        pass
        
    return {
        "country": "Unknown",
        "countryCode": "UN",
        "region": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown"
    }

import asyncio

# Global reference to main asyncio loop
main_loop = None

def run_async_from_thread(coro):
    """Executes a coroutine thread-safely onto the main FastAPI running event loop."""
    global main_loop
    if main_loop is not None:
        try:
            future = asyncio.run_coroutine_threadsafe(coro, main_loop)
            return future.result(timeout=10)
        except Exception:
            pass
            
    # Local loop fallback
    try:
        loop = asyncio.new_event_loop()
        res = loop.run_until_complete(coro)
        loop.close()
        return res
    except Exception as e:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            raise e
        return loop.run_until_complete(coro)

