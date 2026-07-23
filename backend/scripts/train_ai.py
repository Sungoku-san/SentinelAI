import os
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Ensure path includes project root
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config.settings import settings

def generate_synthetic_dataset(n_samples=5000):
    np.random.seed(42)
    
    # Feature definitions:
    # 0: login_attempts (0 - 100)
    # 1: distinct_usernames (0 - 50)
    # 2: distinct_passwords (0 - 100)
    # 3: commands_count (0 - 50)
    # 4: command_length_max (0 - 200)
    # 5: malware_uploaded (0 or 1)
    # 6: scan_requests_count (0 - 100)
    # 7: payload_sql_score (0 - 10)
    # 8: payload_cmd_score (0 - 10)
    # 9: session_duration (0.0 - 600.0 seconds)
    
    data = []
    
    # 7 attack types:
    # 'Normal Login' (added for baseline) / 'Suspicious Login'
    # 'Brute Force'
    # 'Port Scan'
    # 'Credential Stuffing'
    # 'Malware Upload'
    # 'Command Injection'
    # 'Enumeration'
    
    classes = [
        "Suspicious Login",
        "Brute Force",
        "Port Scan",
        "Credential Stuffing",
        "Malware Upload",
        "Command Injection",
        "Enumeration"
    ]
    
    for _ in range(n_samples):
        attack_type = np.random.choice(classes, p=[0.1, 0.2, 0.15, 0.15, 0.1, 0.15, 0.15])
        
        # Initialize default values
        login_attempts = int(np.random.exponential(2))
        distinct_usernames = int(np.random.exponential(1))
        distinct_passwords = int(np.random.exponential(1.5))
        commands_count = int(np.random.exponential(3))
        command_length_max = int(np.random.exponential(15))
        malware_uploaded = 0
        scan_requests_count = int(np.random.exponential(1))
        payload_sql_score = 0
        payload_cmd_score = 0
        session_duration = float(np.random.exponential(30))
        
        # Override according to attack type profiles
        if attack_type == "Suspicious Login":
            login_attempts = int(np.random.randint(1, 4))
            distinct_usernames = 1
            distinct_passwords = int(np.random.randint(1, 4))
            commands_count = int(np.random.randint(0, 3))
            session_duration = float(np.random.randint(5, 60))
            # Out of hours/root log
            
        elif attack_type == "Brute Force":
            login_attempts = int(np.random.randint(15, 100))
            distinct_usernames = int(np.random.randint(1, 3))  # usually targeting one or two users (e.g. root)
            distinct_passwords = login_attempts - int(np.random.randint(0, 5))
            commands_count = 0
            session_duration = float(np.random.randint(20, 300))
            
        elif attack_type == "Credential Stuffing":
            login_attempts = int(np.random.randint(20, 100))
            distinct_usernames = int(np.random.randint(10, 50))  # targeting many users
            distinct_passwords = int(np.random.randint(10, 50))
            commands_count = 0
            session_duration = float(np.random.randint(20, 300))
            
        elif attack_type == "Port Scan":
            login_attempts = 0
            commands_count = 0
            scan_requests_count = int(np.random.randint(15, 100))
            session_duration = float(np.random.randint(2, 20))
            
        elif attack_type == "Malware Upload":
            login_attempts = int(np.random.randint(1, 5))
            commands_count = int(np.random.randint(2, 10))
            malware_uploaded = 1
            command_length_max = int(np.random.randint(30, 150))
            session_duration = float(np.random.randint(10, 120))
            
        elif attack_type == "Command Injection":
            login_attempts = int(np.random.randint(1, 3))
            commands_count = int(np.random.randint(1, 20))
            payload_cmd_score = int(np.random.randint(3, 10))
            command_length_max = int(np.random.randint(40, 200))
            session_duration = float(np.random.randint(5, 180))
            
        elif attack_type == "Enumeration":
            login_attempts = int(np.random.randint(1, 3))
            commands_count = int(np.random.randint(5, 30))
            scan_requests_count = int(np.random.randint(10, 60))  # directory scanner HTTP
            payload_sql_score = int(np.random.randint(0, 2))
            session_duration = float(np.random.randint(10, 240))
            
        data.append([
            login_attempts,
            distinct_usernames,
            distinct_passwords,
            commands_count,
            command_length_max,
            malware_uploaded,
            scan_requests_count,
            payload_sql_score,
            payload_cmd_score,
            session_duration,
            attack_type
        ])
        
    columns = [
        "login_attempts",
        "distinct_usernames",
        "distinct_passwords",
        "commands_count",
        "command_length_max",
        "malware_uploaded",
        "scan_requests_count",
        "payload_sql_score",
        "payload_cmd_score",
        "session_duration",
        "attack_class"
    ]
    
    df = pd.DataFrame(data, columns=columns)
    return df

def train_and_save_model():
    print("Generating synthetic honeypot attack dataset...")
    df = generate_synthetic_dataset(5000)
    
    X = df.drop(columns=["attack_class"])
    y = df["attack_class"]
    
    print("Training RandomForestClassifier model...")
    model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    model.fit(X, y)
    
    # Evaluate model
    accuracy = model.score(X, y)
    print(f"Model trained successfully. Train Accuracy: {accuracy:.4f}")
    
    # Save the model
    model_path = settings.MODEL_PATH
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_and_save_model()
