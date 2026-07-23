import asyncio
import os
import socket
import sys
import threading
import paramiko
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from backend.app.config.settings import settings
from backend.app.services.honeypot_engine import honeypot_engine_instance
from backend.app.services.session_recorder import session_recorder_instance
from backend.app.services.packet_analyzer import packet_analyzer_instance
from backend.app.utils.helpers import get_logger, run_async_from_thread

logger = get_logger("ssh_emulator")

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, session_id: str):
        self.client_ip = client_ip
        self.session_id = session_id
        self.username = None
        self.authenticated = False
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        
        # Log credentials
        # Run in helper thread safely because paramiko callbacks run on paramiko's network thread
        try:
            run_async_from_thread(
                session_recorder_instance.log_credential_attempt(
                    self.session_id, username, password, success=False
                )
            )
            honeypot_engine_instance.register_login_failure(self.client_ip)
            
            # Check adaptive trigger
            should_auth = honeypot_engine_instance.should_accept_brute_force(self.client_ip)
            # Standard backdoors
            if username == "root" and password == "root":
                should_auth = True
            elif username == "admin" and password == "admin123":
                should_auth = True
                
            if should_auth:
                self.authenticated = True
                logger.info(f"SSH authentication accepted for {username}:{password} from {self.client_ip}")
                return paramiko.AUTH_SUCCESSFUL
        except Exception as e:
            logger.error(f"Error in SSH password auth checking: {e}")
        finally:
            pass
            
        return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


class SSHSessionManager:
    def __init__(self, client_socket, client_addr, host_key):
        self.client_socket = client_socket
        self.client_addr = client_addr
        self.host_key = host_key
        self.ip = client_addr[0]
        self.port = client_addr[1]
        self.session_id = None

    def run(self):
        """Processes SSH session negotiation and starts shell console loop."""
        # Create session in recorder
        try:
            self.session_id = run_async_from_thread(
                session_recorder_instance.create_session(self.ip, settings.PORT_SSH, "SSH")
            )
        except Exception as e:
            logger.error(f"Failed to create SSH session: {e}")
            self.client_socket.close()
            return
            
        try:
            transport = paramiko.Transport(self.client_socket)
            transport.add_server_key(self.host_key)
            
            server = SSHServer(self.ip, self.session_id)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                logger.warning("SSH negotiation failed.")
                return

            # Wait for authentication and channel request
            channel = transport.accept(20) # 20 second timeout
            if channel is None:
                logger.warning("No channel shell requested by client within timeout.")
                return
                
            server.event.wait(10)
            if not server.event.is_set():
                logger.warning("PTY Shell was not established.")
                return

            # Start mock shell console loop
            self.handle_shell(channel, server.username)
            
        except Exception as e:
            logger.error(f"Error handling SSH session: {e}")
        finally:
            try:
                self.client_socket.close()
            except Exception:
                pass
            try:
                run_async_from_thread(session_recorder_instance.close_session(self.session_id))
            except Exception:
                pass

    def handle_shell(self, channel, username):
        """Emulates interactive command console shell."""
        channel.send(f"\r\nWelcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-60-generic x86_64)\r\n\r\n")
        channel.send(f" * Documentation:  https://help.ubuntu.com\r\n")
        channel.send(f" * Management:     https://landscape.canonical.com\r\n")
        channel.send(f" * Support:        https://ubuntu.com/advantage\r\n\r\n")
        channel.send(f"Last login: Thu Jul 23 12:44:11 2026 from 192.168.1.50\r\n")
        
        prompt = f"{username}@ubuntu:~# " if username == "root" else f"{username}@ubuntu:~$ "
        channel.send(prompt)
        
        cwd = f"/home/{username}" if username != "root" else "/root"
        
        # Buffer for input lines
        input_buffer = ""
        
        try:
            while True:
                # Read characters from network channel
                data = channel.recv(1024)
                if not data:
                    break
                    
                for char in data:
                    # Carriage return (Enter key)
                    if char == 13 or char == 10:
                        channel.send(b"\r\n")
                        command = input_buffer.strip()
                        input_buffer = ""
                        
                        if not command:
                            channel.send(prompt)
                            continue
                            
                        # Process command
                        cmd_parts = command.split()
                        cmd_base = cmd_parts[0].lower()
                        response = ""
                        
                        if cmd_base == "exit" or cmd_base == "logout":
                            channel.send(b"logout\r\nConnection closed.\r\n")
                            return
                        elif cmd_base == "pwd":
                            response = f"{cwd}\r\n"
                        elif cmd_base == "whoami":
                            response = f"{username}\r\n"
                        elif cmd_base == "id":
                            if username == "root":
                                response = "uid=0(root) gid=0(root) groups=0(root)\r\n"
                            else:
                                response = f"uid=1000({username}) gid=1000({username}) groups=1000({username}),4(adm),27(sudo)\r\n"
                        elif cmd_base == "uname":
                            if "-a" in command:
                                response = "Linux ubuntu 5.15.0-60-generic #66-Ubuntu SMP Fri Jan 20 14:29:49 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
                            else:
                                response = "Linux\r\n"
                        elif cmd_base == "ls":
                            if cwd == "/root" or "home" in cwd:
                                response = "Documents  Downloads  Desktop  .bashrc  .profile\r\n"
                            else:
                                response = "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var\r\n"
                        elif cmd_base == "cd":
                            if len(cmd_parts) > 1:
                                target = cmd_parts[1]
                                if target == "..":
                                    cwd = "/" if cwd == "/root" or cwd == "/home" else os.path.dirname(cwd.rstrip("/"))
                                    if not cwd:
                                        cwd = "/"
                                elif target == "~":
                                    cwd = f"/home/{username}" if username != "root" else "/root"
                                else:
                                    if not target.startswith("/"):
                                        cwd = f"{cwd.rstrip('/')}/{target}"
                                    else:
                                        cwd = target
                            response = ""
                        elif cmd_base == "cat":
                            if len(cmd_parts) > 1:
                                filepath = cmd_parts[1]
                                if "passwd" in filepath:
                                    response = (
                                        "root:x:0:0:root:/root:/bin/bash\r\n"
                                        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                                        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
                                        f"{username}:x:1000:1000::/home/{username}:/bin/bash\r\n"
                                    )
                                elif "shadow" in filepath:
                                    response = (
                                        "root:$6$d98k1j9s$8k2kd92kd92kd92kd92kdu2k8s9kd82kd92kd92kd92kd92kdu12k:19223:0:99999:7:::\r\n"
                                        f"{username}:$6$x82jkf8s$9k2kd92kd92kd92kd92kdu2k8s9kd82kd92kd92kd92kd92kdu12k:19223:0:99999:7:::\r\n"
                                    )
                                else:
                                    response = f"cat: {filepath}: No such file or directory\r\n"
                            else:
                                response = "cat: missing operand\r\n"
                        elif cmd_base in ("wget", "curl"):
                            # Mock download link
                            response = f"Connecting to remote host... Connected.\r\nDownloading payload... Done.\r\n"
                        elif cmd_base == "history":
                            response = "  1  id\r\n  2  uname -a\r\n  3  pwd\r\n  4  ls -la\r\n  5  history\r\n"
                        else:
                            # Simulated bash command execution response
                            response = f"bash: {cmd_base}: command not found\r\n"
                            
                        # Log command
                        run_async_from_thread(
                            session_recorder_instance.log_command_execution(self.session_id, command, response)
                        )
                        
                        channel.send(response)
                        channel.send(prompt)
                        
                    # Backspace
                    elif char == 8 or char == 127:
                        if len(input_buffer) > 0:
                            input_buffer = input_buffer[:-1]
                            channel.send(b"\b \b") # Backspace character on terminal
                    # Normal char
                    else:
                        char_str = chr(char)
                        input_buffer += char_str
                        channel.send(char_str.encode('utf-8'))
                        
        except Exception as e:
            logger.error(f"Error in active SSH shell stream: {e}")
        finally:
            channel.close()


class SSHEmulator:
    def __init__(self):
        self.server_socket = None
        self.running = False
        self.host_key = None
        self.thread = None

    def _ensure_host_key(self):
        """Loads or dynamically generates a server host RSA private key."""
        key_file = os.path.join(settings.LOG_DIR, "id_rsa_ssh")
        if not os.path.exists(key_file):
            logger.info("Generating dynamic RSA private host key for SSH server...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_file, "wb") as f:
                f.write(pem)
                
        self.host_key = paramiko.RSAKey.from_private_key_file(key_file)

    async def start(self):
        """Starts the SSH Server thread."""
        self._ensure_host_key()
        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        logger.info(f"SSH Honeypot Emulator listening on port {settings.PORT_SSH}...")

    def _run_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind(('0.0.0.0', settings.PORT_SSH))
            self.server_socket.listen(100)
            
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, client_addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except Exception:
                    break
                    
                logger.info(f"Incoming SSH connection from {client_addr[0]}:{client_addr[1]}")
                
                # Log simulated packet
                packet_analyzer_instance.log_simulated_packet(client_addr[0], settings.PORT_SSH, "TCP")
                
                # Hand connection over to thread pool
                session_mgr = SSHSessionManager(client_socket, client_addr, self.host_key)
                t = threading.Thread(target=session_mgr.run, daemon=True)
                t.start()
                
        except Exception as e:
            logger.error(f"SSH socket server crash: {e}")
        finally:
            self.server_socket.close()

    async def stop(self):
        """Stops the SSH Server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("SSH Honeypot Emulator stopped.")

ssh_emulator_instance = SSHEmulator()
