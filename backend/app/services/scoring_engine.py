from backend.app.utils.helpers import get_logger

logger = get_logger("scoring_engine")

class ScoringEngine:
    def calculate_threat_score(self, features: dict) -> dict:
        """Calculates security threat score (0-100) and maps to threat level."""
        # Extract features
        login_attempts = int(features.get("login_attempts", 0))
        commands_count = int(features.get("commands_count", 0))
        malware_uploaded = int(features.get("malware_uploaded", 0))
        scan_requests = int(features.get("scan_requests_count", 0))
        payload_sql = int(features.get("payload_sql_score", 0))
        payload_cmd = int(features.get("payload_cmd_score", 0))
        
        # Base score calculations
        score = 10.0  # Initial connection baseline
        
        # Accumulators
        login_penalty = min(login_attempts * 2.0, 30.0)
        command_penalty = min(commands_count * 3.0, 30.0)
        malware_penalty = 40.0 if malware_uploaded > 0 else 0.0
        scan_penalty = min(scan_requests * 1.5, 25.0)
        exploit_penalty = min((payload_sql + payload_cmd) * 5.0, 30.0)
        
        score += login_penalty + command_penalty + malware_penalty + scan_penalty + exploit_penalty
        
        # Clamp score between 0 and 100
        final_score = float(max(0.0, min(100.0, score)))
        
        # Map to threat levels
        if final_score <= 30.0:
            level = "Low"
        elif final_score <= 60.0:
            level = "Medium"
        elif final_score <= 85.0:
            level = "High"
        else:
            level = "Critical"
            
        return {
            "score": final_score,
            "level": level,
            "breakdown": {
                "login_penalty": login_penalty,
                "command_penalty": command_penalty,
                "malware_penalty": malware_penalty,
                "scan_penalty": scan_penalty,
                "exploit_penalty": exploit_penalty
            }
        }

scoring_engine_instance = ScoringEngine()
