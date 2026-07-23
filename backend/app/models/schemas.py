from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

class UserProfileResponse(BaseModel):
    username: str

# Session schema details
class CredentialAttempt(BaseModel):
    username: str
    password: str
    timestamp: datetime
    success: bool

class CommandExecution(BaseModel):
    command: str
    response: str
    timestamp: datetime

class UploadedFile(BaseModel):
    filename: str
    size: int
    md5: str
    sha256: str
    timestamp: datetime

class SessionStats(BaseModel):
    login_attempts: int
    distinct_usernames: int
    distinct_passwords: int
    commands_count: int
    command_length_max: int
    malware_uploaded: int
    scan_requests_count: int
    payload_sql_score: int
    payload_cmd_score: int
    session_duration: float

class SessionResponse(BaseModel):
    session_id: str
    ip_address: str
    port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime] = None
    credentials_attempts: List[CredentialAttempt] = []
    commands: List[CommandExecution] = []
    uploaded_files: List[UploadedFile] = []
    threat_score: float
    threat_level: str
    ai_classification: str
    ai_explanation: str
    geo_location: Dict[str, Any]
    features: SessionStats

class SystemStatusResponse(BaseModel):
    ssh_port: int
    http_port: int
    ftp_port: int
    telnet_port: int
    ssh_running: bool
    http_running: bool
    ftp_running: bool
    telnet_running: bool
    packet_stats: Dict[str, Any]

class DashboardStatsResponse(BaseModel):
    total_sessions: int
    total_attacks: int
    critical_alerts: int
    unique_ips: int
    protocol_distribution: Dict[str, int]
    threat_level_distribution: Dict[str, int]
    top_ips: List[Dict[str, Any]]
