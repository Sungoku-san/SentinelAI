import asyncio
import os
import time
from backend.app.config.settings import settings
from backend.app.utils.helpers import get_logger, get_file_hash

logger = get_logger("honeypot_engine")

class AdaptiveHoneypotEngine:
    def __init__(self):
        # Dictionary tracking IP-based profiles:
        # { ip_address: { login_failures: int, directories_scanned: int, ssh_success_count: int, last_seen: float } }
        self.attacker_profiles = {}

    def get_profile(self, ip_address: str) -> dict:
        """Retrieves or initializes the adaptive profile for a given IP."""
        if ip_address not in self.attacker_profiles:
            self.attacker_profiles[ip_address] = {
                "login_failures": 0,
                "directories_scanned": 0,
                "ssh_success_count": 0,
                "last_seen": time.time()
            }
        return self.attacker_profiles[ip_address]

    def register_login_failure(self, ip_address: str):
        """Increments login failure counts to enable adaptive triggers."""
        profile = self.get_profile(ip_address)
        profile["login_failures"] += 1
        profile["last_seen"] = time.time()
        logger.info(f"IP {ip_address} has {profile['login_failures']} login failures registered.")

    def register_directory_scan(self, ip_address: str):
        """Increments path scan triggers."""
        profile = self.get_profile(ip_address)
        profile["directories_scanned"] += 1
        profile["last_seen"] = time.time()
        logger.info(f"IP {ip_address} directory scans count: {profile['directories_scanned']}")

    async def get_connection_delay(self, ip_address: str) -> float:
        """Calculates adaptive network delay (tarpitting) for the IP."""
        profile = self.get_profile(ip_address)
        failures = profile["login_failures"]
        
        # Calculate dynamic delay
        if failures >= settings.BRUTE_FORCE_THRESHOLD:
            # Scale delay progressively up to MAX TARPIT LATENCY
            delay = min((failures - settings.BRUTE_FORCE_THRESHOLD) * 1.0 + 1.0, settings.TARPIT_LATENCY_MAX)
            logger.info(f"Adaptive Action: Injecting {delay:.2f}s network delay for {ip_address}")
            return delay
        return 0.0

    def should_accept_brute_force(self, ip_address: str) -> bool:
        """Triggers the 'Credential Capture Sandbox' once the attacker attempts too many logins."""
        profile = self.get_profile(ip_address)
        # Let's say if they try login more than 8 times, we let them in to track post-exploit behavior!
        if profile["login_failures"] >= 8:
            logger.info(f"Adaptive Action: Auto-authenticating attacker {ip_address} to capture post-compromise behaviors.")
            return True
        return False

    def generate_dynamic_http_decoy(self, path: str) -> str:
        """Generates dynamic fake files and directories depending on path requested."""
        path_lower = path.lower()
        
        # Decoy templates
        if "env" in path_lower:
            return (
                "# Environment Configurations\n"
                "DB_HOST=127.0.0.1\n"
                "DB_USER=production_admin\n"
                "DB_PASS=S3cureP@ssw0rd!_99\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "SECRET_KEY=e834a5d8920194857bca889201726a88b776a33b\n"
                "TELEGRAM_BOT_TOKEN=7891011:AAF456789abcde\n"
            )
        elif "config" in path_lower:
            return (
                "<?php\n"
                "define('DB_SERVER', 'localhost');\n"
                "define('DB_USERNAME', 'db_web_usr');\n"
                "define('DB_PASSWORD', 'WebAdminP@ss123!');\n"
                "define('DB_NAME', 'customer_portal');\n"
                "$conn = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);\n"
                "if($conn === false){ die('ERROR: Could not connect.'); }\n"
                "?>"
            )
        elif "sql" in path_lower or "backup" in path_lower:
            return (
                "-- SentinelAI Decoy Database Backup Dump\n"
                "-- Created: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n"
                "CREATE DATABASE IF NOT EXISTS `users_db`;\n"
                "USE `users_db`;\n"
                "CREATE TABLE `admin` (\n"
                "  `id` int(11) NOT NULL AUTO_INCREMENT,\n"
                "  `username` varchar(50) NOT NULL,\n"
                "  `password` varchar(255) NOT NULL,\n"
                "  PRIMARY KEY (`id`)\n"
                ") ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;\n"
                "INSERT INTO `admin` VALUES (1,'administrator','$2y$10$O9428/dsk82kd92kd92kdu2k8s9kd82kd92kd92kd92kd92kdu12k');\n"
            )
        else:
            # Generic directory traversal/enumeration response
            return (
                "<html>\n"
                "<head><title>Index of " + path + "</title></head>\n"
                "<body>\n"
                "<h1>Index of " + path + "</h1>\n"
                "<hr>\n"
                "<pre>\n"
                "<a href='../'>../</a>\n"
                "<a href='backup.sql'>backup.sql</a>             " + time.strftime("%d-%b-%Y %H:%M") + "        20485\n"
                "<a href='config.php.bak'>config.php.bak</a>         " + time.strftime("%d-%b-%Y %H:%M") + "         1294\n"
                "<a href='.env'>.env</a>                   " + time.strftime("%d-%b-%Y %H:%M") + "          415\n"
                "</pre>\n"
                "<hr>\n"
                "</body>\n"
                "</html>\n"
            )

    async def isolate_and_quarantine_file(self, filename: str, content: bytes) -> dict:
        """Safely saves malware files to the quarantine directory, generating dynamic metadata hashes."""
        # Generate sanitized name
        safe_filename = "".join(c for c in filename if c.isalnum() or c in (".", "_", "-")).strip()
        if not safe_filename:
            safe_filename = f"malware_{int(time.time())}.bin"
            
        quarantine_path = os.path.join(settings.QUARANTINE_DIR, f"{int(time.time())}_{safe_filename}")
        
        try:
            # Run in executor to not block async thread
            await asyncio.to_thread(self._write_quarantine, quarantine_path, content)
            
            # Generate hashes
            hashes = get_file_hash(quarantine_path)
            logger.info(f"Adaptive Action: Quarantined suspicious payload {safe_filename} to {quarantine_path}")
            
            return {
                "filename": safe_filename,
                "size": len(content),
                "quarantine_path": quarantine_path,
                "hashes": hashes,
                "success": True
            }
        except Exception as e:
            logger.error(f"Failed to quarantine file {safe_filename}: {e}")
            return {
                "filename": safe_filename,
                "size": len(content),
                "quarantine_path": "",
                "hashes": {"md5": "", "sha256": ""},
                "success": False,
                "error": str(e)
            }

    def _write_quarantine(self, path: str, content: bytes):
        with open(path, "wb") as f:
            f.write(content)

honeypot_engine_instance = AdaptiveHoneypotEngine()
