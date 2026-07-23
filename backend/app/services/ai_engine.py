import os
import joblib
import numpy as np
import pandas as pd
from backend.app.config.settings import settings
from backend.app.utils.helpers import get_logger

logger = get_logger("ai_engine")

class AIEngine:
    def __init__(self):
        self.model = None
        self.feature_names = [
            "login_attempts",
            "distinct_usernames",
            "distinct_passwords",
            "commands_count",
            "command_length_max",
            "malware_uploaded",
            "scan_requests_count",
            "payload_sql_score",
            "payload_cmd_score",
            "session_duration"
        ]
        self.load_model()
        
    def load_model(self):
        """Loads the trained RF model, falling back to rule-based engine if not found."""
        if os.path.exists(settings.MODEL_PATH):
            try:
                self.model = joblib.load(settings.MODEL_PATH)
                logger.info(f"AI Threat Model loaded successfully from {settings.MODEL_PATH}")
            except Exception as e:
                logger.error(f"Failed to load AI model: {e}. Falling back to rule-based engine.")
                self.model = None
        else:
            logger.warning(f"AI Model not found at {settings.MODEL_PATH}. Starting with heuristic rules fallback.")
            self.model = None

    def classify_session_behavior(self, features: dict) -> dict:
        """Classifies a threat session and generates detailed explanation."""
        # Convert inputs to float
        input_data = {k: float(features.get(k, 0)) for k in self.feature_names}
        
        if self.model is not None:
            try:
                # Format to matching pandas DataFrame structure
                df = pd.DataFrame([input_data])
                prediction = self.model.predict(df)[0]
                probabilities = self.model.predict_proba(df)[0]
                classes = self.model.classes_
                confidence = float(max(probabilities))
                
                explanation = self.explain_prediction(input_data, prediction, confidence)
                
                return {
                    "class": prediction,
                    "confidence": confidence,
                    "explanation": explanation,
                    "features": input_data,
                    "using_ml": True
                }
            except Exception as e:
                logger.error(f"Error during ML prediction: {e}. Using heuristic fallback.")
                
        # Rule-based / Heuristic Fallback
        return self._heuristic_classify(input_data)

    def _heuristic_classify(self, features: dict) -> dict:
        """Heuristic fallback classifier."""
        login_attempts = features["login_attempts"]
        distinct_usernames = features["distinct_usernames"]
        distinct_passwords = features["distinct_passwords"]
        commands_count = features["commands_count"]
        cmd_score = features["payload_cmd_score"]
        sql_score = features["payload_sql_score"]
        malware = features["malware_uploaded"]
        scan = features["scan_requests_count"]
        
        # Classification rules
        if malware > 0:
            pred_class = "Malware Upload"
            confidence = 0.95
        elif cmd_score >= 3 or (commands_count > 0 and cmd_score >= 2):
            pred_class = "Command Injection"
            confidence = 0.90
        elif sql_score >= 3:
            pred_class = "Command Injection"  # or Database exploit
            confidence = 0.85
        elif login_attempts >= 10 and distinct_usernames >= 5:
            pred_class = "Credential Stuffing"
            confidence = 0.88
        elif login_attempts >= settings.BRUTE_FORCE_THRESHOLD:
            pred_class = "Brute Force"
            confidence = 0.85
        elif scan >= 10:
            pred_class = "Enumeration"
            confidence = 0.80
        elif scan > 0 and commands_count == 0 and login_attempts == 0:
            pred_class = "Port Scan"
            confidence = 0.75
        else:
            pred_class = "Suspicious Login"
            confidence = 0.60
            
        explanation = self.explain_prediction(features, pred_class, confidence)
        
        return {
            "class": pred_class,
            "confidence": confidence,
            "explanation": explanation,
            "features": features,
            "using_ml": False
        }

    def explain_prediction(self, features: dict, predicted_class: str, confidence: float) -> str:
        """Generates clear, human-readable explainable AI (XAI) rationale."""
        login_attempts = int(features.get("login_attempts", 0))
        distinct_usernames = int(features.get("distinct_usernames", 0))
        distinct_passwords = int(features.get("distinct_passwords", 0))
        commands_count = int(features.get("commands_count", 0))
        cmd_score = int(features.get("payload_cmd_score", 0))
        sql_score = int(features.get("payload_sql_score", 0))
        malware = int(features.get("malware_uploaded", 0))
        scan = int(features.get("scan_requests_count", 0))
        duration = float(features.get("session_duration", 0.0))

        confidence_percent = int(confidence * 100)
        
        reasons = []
        mitigations = []
        
        if predicted_class == "Brute Force":
            reasons.append(f"high frequency of authentication attempts ({login_attempts} times) targeting a limited number of username structures ({distinct_usernames} unique username(s)) using multiple password combinations ({distinct_passwords} tried)")
            mitigations.append("Implement authentication rate-limiting, IP tarpitting, and enforce multi-factor authentication (MFA). Block this IP on the perimeter firewall.")
            
        elif predicted_class == "Credential Stuffing":
            reasons.append(f"automated spraying pattern consisting of {login_attempts} login requests spread across a wide list of {distinct_usernames} usernames and {distinct_passwords} password variants, indicating a leaked credential list reuse attempt")
            mitigations.append("Enable CAPTCHA on authentication endpoints, enforce account lockout rules, and audit user accounts against known credential dumps.")
            
        elif predicted_class == "Malware Upload":
            reasons.append(f"direct transmission and execution of file write commands, culminating in the upload of unrecognized or suspicious binaries/scripts (quarantined and hashed)")
            mitigations.append("Restrict directory write permissions, isolate file upload directories, run services with minimal privileges, and implement real-time file integrity monitoring (FIM).")
            
        elif predicted_class == "Command Injection":
            reasons.append(f"presence of command chaining metacharacters (e.g., ;, &&, |) or restricted keywords (e.g., wget, curl, chmod) in inputs (Command payload risk index: {cmd_score})")
            mitigations.append("Validate and sanitize all user inputs, use parameterized execution libraries, restrict outbound internet access from production systems to prevent reverse shells.")
            
        elif predicted_class == "Enumeration":
            reasons.append(f"abnormal number of resource traversal requests ({scan} occurrences) seeking common configuration folders, backups, or files (e.g., .env, config.php, .git)")
            mitigations.append("Disable directory indexing, return standard 404 responses instead of detailed application stack errors, and deploy web application firewalls (WAF) to filter path scanners.")
            
        elif predicted_class == "Port Scan":
            reasons.append(f"sequential network probes ({scan} hits) across multiple system endpoints in a brief period ({duration:.1f}s) without initiating active session transactions")
            mitigations.append("Implement scan-detection rules on firewalls, restrict open port visibility, and deploy network intrusion detection systems (NIDS).")
            
        else: # Suspicious Login
            reasons.append(f"anomalous or unauthorized connection parameters, with few interactive inputs ({commands_count} commands run) after initial authentication")
            mitigations.append("Audit connection source IP reputation, implement geographic restrictions (Geo-IP blocking), and review active user permissions.")
            
        reason_str = ", ".join(reasons)
        mitigation_str = " ".join(mitigations)
        
        explanation = (
            f"The system classified this session as '{predicted_class}' with {confidence_percent}% confidence. "
            f"This classification is triggered by {reason_str}. "
            f"Recommended Mitigations: {mitigation_str}"
        )
        return explanation

ai_engine_instance = AIEngine()
