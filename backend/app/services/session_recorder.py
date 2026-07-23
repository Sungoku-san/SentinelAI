import uuid
import datetime
from backend.app.database.mongodb import get_database
from backend.app.services.ai_engine import ai_engine_instance
from backend.app.services.behavior_analyzer import behavior_analyzer_instance
from backend.app.services.scoring_engine import scoring_engine_instance
from backend.app.utils.helpers import get_logger, get_ip_details

logger = get_logger("session_recorder")

class SessionRecorder:
    def __init__(self):
        # In-memory session store for rapid lookup of active connections
        self.active_sessions = {}

    async def create_session(self, ip_address: str, port: int, protocol: str) -> str:
        """Creates a new attacker session document in MongoDB and in-memory store."""
        session_id = str(uuid.uuid4())
        
        # Geolocation lookup
        geo_details = await get_ip_details(ip_address)
        
        session_doc = {
            "session_id": session_id,
            "ip_address": ip_address,
            "port": port,
            "protocol": protocol,
            "start_time": datetime.datetime.utcnow(),
            "end_time": None,
            "credentials_attempts": [],
            "commands": [],
            "uploaded_files": [],
            "scan_requests": [],
            "threat_score": 10.0,
            "threat_level": "Low",
            "ai_classification": "Suspicious Login",
            "ai_explanation": "Initial connection established.",
            "geo_location": geo_details,
            "features": {
                "login_attempts": 0,
                "distinct_usernames": 0,
                "distinct_passwords": 0,
                "commands_count": 0,
                "command_length_max": 0,
                "malware_uploaded": 0,
                "scan_requests_count": 0,
                "payload_sql_score": 0,
                "payload_cmd_score": 0,
                "session_duration": 0.0
            }
        }
        
        self.active_sessions[session_id] = session_doc
        
        # Save to DB
        db = get_database()
        if db is not None:
            try:
                await db.sessions.insert_one(session_doc)
            except Exception as e:
                logger.error(f"Error saving new session to MongoDB: {e}")
                
        logger.info(f"Created session {session_id} for {ip_address} via {protocol}")
        return session_id

    async def log_credential_attempt(self, session_id: str, username: str, password: str, success: bool = False):
        """Logs a login attempt inside the session."""
        if session_id not in self.active_sessions:
            logger.warning(f"Attempted to log credential for inactive session: {session_id}")
            return
            
        session = self.active_sessions[session_id]
        attempt = {
            "username": username,
            "password": password,
            "timestamp": datetime.datetime.utcnow(),
            "success": success
        }
        
        session["credentials_attempts"].append(attempt)
        
        # Update features
        feats = session["features"]
        feats["login_attempts"] += 1
        
        # Re-evaluate distinct lists
        usernames = set(c["username"] for c in session["credentials_attempts"])
        passwords = set(c["password"] for c in session["credentials_attempts"])
        feats["distinct_usernames"] = len(usernames)
        feats["distinct_passwords"] = len(passwords)
        
        await self._recompute_threat_intelligence(session_id)

    async def log_command_execution(self, session_id: str, command: str, response: str = ""):
        """Logs a command execution inside the session."""
        if session_id not in self.active_sessions:
            logger.warning(f"Attempted to log command for inactive session: {session_id}")
            return
            
        session = self.active_sessions[session_id]
        cmd_entry = {
            "command": command,
            "response": response[:1000],  # cap response stored in DB
            "timestamp": datetime.datetime.utcnow()
        }
        session["commands"].append(cmd_entry)
        
        # Update features
        feats = session["features"]
        feats["commands_count"] += 1
        feats["command_length_max"] = max(feats["command_length_max"], len(command))
        
        # Evaluate command payload scores
        # Simple SQL injection indicator checks
        sql_indicators = ["select ", "union ", "insert ", "update ", "delete ", "drop ", "' or ", "or 1=1"]
        if any(ind in command.lower() for ind in sql_indicators):
            feats["payload_sql_score"] += 1
            
        # Command injection indicators
        cmd_indicators = [";", "&&", "||", "|", "wget ", "curl ", "chmod ", "nohup ", "python ", "perl ", "gcc "]
        if any(ind in command.lower() for ind in cmd_indicators):
            feats["payload_cmd_score"] += 1
            
        await self._recompute_threat_intelligence(session_id)

    async def log_file_upload(self, session_id: str, filename: str, file_size: int, file_hash: dict, quarantine_path: str):
        """Logs a file upload."""
        if session_id not in self.active_sessions:
            return
            
        session = self.active_sessions[session_id]
        upload_entry = {
            "filename": filename,
            "size": file_size,
            "md5": file_hash.get("md5", ""),
            "sha256": file_hash.get("sha256", ""),
            "quarantine_path": quarantine_path,
            "timestamp": datetime.datetime.utcnow()
        }
        session["uploaded_files"].append(upload_entry)
        
        # Update features
        session["features"]["malware_uploaded"] = 1
        
        await self._recompute_threat_intelligence(session_id)

    async def log_scan_request(self, session_id: str, requested_resource: str, method: str = "GET"):
        """Logs an enumeration/scanning request (primarily HTTP)."""
        if session_id not in self.active_sessions:
            return
            
        session = self.active_sessions[session_id]
        scan_entry = {
            "resource": requested_resource,
            "method": method,
            "timestamp": datetime.datetime.utcnow()
        }
        session["scan_requests"].append(scan_entry)
        
        # Update features
        session["features"]["scan_requests_count"] += 1
        
        await self._recompute_threat_intelligence(session_id)

    async def close_session(self, session_id: str):
        """Marks the session as closed and saves final state to MongoDB."""
        if session_id not in self.active_sessions:
            return
            
        session = self.active_sessions[session_id]
        session["end_time"] = datetime.datetime.utcnow()
        
        # Update session duration feature
        duration = (session["end_time"] - session["start_time"]).total_seconds()
        session["features"]["session_duration"] = duration
        
        # Recompute final AI score
        await self._recompute_threat_intelligence(session_id)
        
        # Save to DB and evict from memory
        db = get_database()
        if db is not None:
            try:
                await db.sessions.replace_one({"session_id": session_id}, session)
                
                # Log attack summary to the main attack_logs collection
                log_entry = {
                    "timestamp": session["end_time"],
                    "session_id": session_id,
                    "ip_address": session["ip_address"],
                    "protocol": session["protocol"],
                    "threat_score": session["threat_score"],
                    "threat_level": session["threat_level"],
                    "ai_classification": session["ai_classification"]
                }
                await db.attack_logs.insert_one(log_entry)
            except Exception as e:
                logger.error(f"Error saving session details on close: {e}")
                
        del self.active_sessions[session_id]
        logger.info(f"Closed session {session_id}. Duration: {duration:.1f}s, Score: {session['threat_score']}")

    async def _recompute_threat_intelligence(self, session_id: str):
        """Re-runs the AI engine classification, scoring, and updates DB."""
        session = self.active_sessions[session_id]
        
        # Update current duration
        duration = (datetime.datetime.utcnow() - session["start_time"]).total_seconds()
        session["features"]["session_duration"] = duration
        
        # AI Classification
        ai_result = ai_engine_instance.classify_session_behavior(session["features"])
        session["ai_classification"] = ai_result["class"]
        session["ai_explanation"] = ai_result["explanation"]
        
        # Threat Scoring
        score_result = scoring_engine_instance.calculate_threat_score(session["features"])
        
        # Keep old/new threat level info to check for state increases
        old_level = session["threat_level"]
        
        session["threat_score"] = score_result["score"]
        session["threat_level"] = score_result["level"]
        
        # Update DB asynchronously in background
        db = get_database()
        if db is not None:
            try:
                await db.sessions.update_one(
                    {"session_id": session_id},
                    {
                        "$set": {
                            "credentials_attempts": session["credentials_attempts"],
                            "commands": session["commands"],
                            "uploaded_files": session["uploaded_files"],
                            "scan_requests": session["scan_requests"],
                            "threat_score": session["threat_score"],
                            "threat_level": session["threat_level"],
                            "ai_classification": session["ai_classification"],
                            "ai_explanation": session["ai_explanation"],
                            "features": session["features"],
                            "end_time": session["end_time"]
                        }
                    }
                )
            except Exception as e:
                logger.error(f"Failed to update session details: {e}")
                
        # Handle Alerts
        if old_level != session["threat_level"] and session["threat_level"] in ["High", "Critical"]:
            # Trigger alert notification service import locally to avoid circular dependencies
            from backend.app.services.notification_service import notification_service_instance
            await notification_service_instance.send_alert(session)

session_recorder_instance = SessionRecorder()
