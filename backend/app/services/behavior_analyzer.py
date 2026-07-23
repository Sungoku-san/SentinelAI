from backend.app.utils.helpers import get_logger

logger = get_logger("behavior_analyzer")

# MITRE ATT&CK tactics mapping for common honeypot behaviors
MITRE_MAPPING = {
    # Discovery
    "whoami": {"id": "T1033", "tactic": "Discovery", "name": "System Owner/User Discovery"},
    "id": {"id": "T1033", "tactic": "Discovery", "name": "System Owner/User Discovery"},
    "uname": {"id": "T1082", "tactic": "Discovery", "name": "System Information Discovery"},
    "ifconfig": {"id": "T1016", "tactic": "Discovery", "name": "System Network Configuration Discovery"},
    "ip": {"id": "T1016", "tactic": "Discovery", "name": "System Network Configuration Discovery"},
    "netstat": {"id": "T1049", "tactic": "Discovery", "name": "System Network Connections Discovery"},
    "ps": {"id": "T1057", "tactic": "Discovery", "name": "Process Discovery"},
    "ls": {"id": "T1083", "tactic": "Discovery", "name": "File and Directory Discovery"},
    "find": {"id": "T1083", "tactic": "Discovery", "name": "File and Directory Discovery"},
    
    # Credential Access
    "cat /etc/passwd": {"id": "T1003.008", "tactic": "Credential Access", "name": "OS Credential Dumping: /etc/passwd"},
    "cat /etc/shadow": {"id": "T1003.008", "tactic": "Credential Access", "name": "OS Credential Dumping: /etc/shadow"},
    
    # Execution / Lateral Movement
    "sh": {"id": "T1059.004", "tactic": "Execution", "name": "Command and Scripting Interpreter: Unix Shell"},
    "bash": {"id": "T1059.004", "tactic": "Execution", "name": "Command and Scripting Interpreter: Unix Shell"},
    "python": {"id": "T1059.006", "tactic": "Execution", "name": "Command and Scripting Interpreter: Python"},
    "perl": {"id": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    
    # Command and Control
    "wget": {"id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer"},
    "curl": {"id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer"},
    "scp": {"id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer"},
    "ftp": {"id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer"},
    
    # Defense Evasion / Persistence
    "chmod": {"id": "T1222.002", "tactic": "Defense Evasion", "name": "File and Directory Permissions Modification: Linux File Permissions"},
    "rm": {"id": "T1070.004", "tactic": "Defense Evasion", "name": "Indicator Removal on Host: File Deletion"},
    "mv": {"id": "T1070.004", "tactic": "Defense Evasion", "name": "Indicator Removal on Host: File Movement"},
    "history": {"id": "T1070.003", "tactic": "Defense Evasion", "name": "Indicator Removal on Host: Clear Command History"},
    "echo >": {"id": "T1070.004", "tactic": "Defense Evasion", "name": "Indicator Removal on Host: File Truncation"},
}

class BehaviorAnalyzer:
    def analyze_command_sequence(self, commands: list) -> dict:
        """Analyzes a sequence of commands to map to MITRE ATT&CK tactics."""
        tactics_triggered = set()
        techniques = []
        phases = []
        
        for cmd_entry in commands:
            cmd = cmd_entry.get("command", "").strip().lower()
            
            # Simple keyword matching on the command string
            matched = False
            for trigger, detail in MITRE_MAPPING.items():
                if trigger in cmd:
                    tactics_triggered.add(detail["tactic"])
                    if detail not in techniques:
                        techniques.append(detail)
                    matched = True
            
            # If not explicitly matched but contains pipe/redirect, mark as evasion/scripting
            if not matched:
                if ">" in cmd or ">>" in cmd:
                    techniques.append({
                        "id": "T1059",
                        "tactic": "Execution",
                        "name": "Scripting redirection"
                    })
                    tactics_triggered.add("Execution")
                if ";" in cmd or "&&" in cmd or "|" in cmd:
                    techniques.append({
                        "id": "T1059",
                        "tactic": "Execution",
                        "name": "Command chaining execution"
                    })
                    tactics_triggered.add("Execution")
                    
        # Construct stages summary
        tactic_list = list(tactics_triggered)
        
        # Mapping to simple phases of attacker lifecycle
        if "Discovery" in tactic_list:
            phases.append("Reconnaissance / Discovery")
        if "Credential Access" in tactic_list:
            phases.append("Credential Gathering")
        if "Execution" in tactic_list or "Command and Control" in tactic_list:
            phases.append("Active Exploit Execution")
        if "Defense Evasion" in tactic_list:
            phases.append("System Modification / Evasion")
            
        if not phases:
            if commands:
                phases.append("Interactive Probe")
            else:
                phases.append("Initial Connection Probe")
                
        return {
            "mitre_tactics": tactic_list,
            "mitre_techniques": techniques,
            "attack_lifecycle_phases": phases,
            "risk_indicators_count": len(techniques)
        }

behavior_analyzer_instance = BehaviorAnalyzer()
