import asyncio
import socket
from backend.app.config.settings import settings
from backend.app.services.honeypot_engine import honeypot_engine_instance
from backend.app.services.session_recorder import session_recorder_instance
from backend.app.services.packet_analyzer import packet_analyzer_instance
from backend.app.utils.helpers import get_logger

logger = get_logger("ftp_emulator")

class FTPSessionHandler:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, session_id: str, ip: str):
        self.reader = reader
        self.writer = writer
        self.session_id = session_id
        self.ip = ip
        self.username = ""
        self.cwd = "/home/ftp"
        self.pasv_server = None
        self.pasv_port = 0
        self.data_connection_future = None
        self.authenticated = False

    async def run(self):
        """Runs the interactive command loop for the FTP connection."""
        try:
            self.writer.write(b"220 SentinelAI Secure FTP Server Ready.\r\n")
            await self.writer.drain()
            
            while True:
                line_data = await self.reader.readline()
                if not line_data:
                    break
                    
                line = line_data.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue
                    
                parts = line.split(maxsplit=1)
                cmd = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""
                
                # Log command
                await session_recorder_instance.log_command_execution(self.session_id, f"FTP: {line}", "")
                
                # Route command
                if cmd == "QUIT":
                    self.writer.write(b"221 Goodbye.\r\n")
                    await self.writer.drain()
                    break
                elif cmd == "USER":
                    self.username = args
                    self.writer.write(b"331 User name okay, need password.\r\n")
                    await self.writer.drain()
                elif cmd == "PASS":
                    # Authenticate attacker
                    self.authenticated = True
                    await session_recorder_instance.log_credential_attempt(
                        self.session_id, self.username, args, success=True
                    )
                    # Keep record of login events
                    honeypot_engine_instance.register_login_failure(self.ip)
                    
                    self.writer.write(b"230 User logged in, proceed.\r\n")
                    await self.writer.drain()
                elif not self.authenticated:
                    self.writer.write(b"530 Please login with USER and PASS.\r\n")
                    await self.writer.drain()
                elif cmd == "SYST":
                    self.writer.write(b"215 UNIX Type: L8\r\n")
                    await self.writer.drain()
                elif cmd == "PWD":
                    self.writer.write(f'257 "{self.cwd}" is current directory.\r\n'.encode('utf-8'))
                    await self.writer.drain()
                elif cmd == "CWD":
                    # Simple mock CWD
                    if args.startswith("/"):
                        self.cwd = args
                    else:
                        self.cwd = f"{self.cwd.rstrip('/')}/{args}"
                    self.writer.write(b"250 Directory successfully changed.\r\n")
                    await self.writer.drain()
                elif cmd == "TYPE":
                    self.writer.write(b"200 Type set to I.\r\n")
                    await self.writer.drain()
                elif cmd == "PASV":
                    await self._setup_passive_mode()
                elif cmd == "LIST":
                    await self._handle_list()
                elif cmd == "RETR":
                    await self._handle_retr(args)
                elif cmd == "STOR":
                    await self._handle_stor(args)
                else:
                    self.writer.write(b"500 Command not understood.\r\n")
                    await self.writer.drain()
                    
        except Exception as e:
            logger.error(f"FTP connection handler exception: {e}")
        finally:
            await self._cleanup()

    async def _setup_passive_mode(self):
        """Sets up a passive data listener socket for files or directories listings."""
        if self.pasv_server:
            self.pasv_server.close()
            
        # Select local interface IP and random free port
        loop = asyncio.get_running_loop()
        
        # Binds to wildcard but we map the control port host to peer connections
        self.pasv_server = await asyncio.start_server(
            self._handle_data_connection, '0.0.0.0', 0
        )
        self.pasv_port = self.pasv_server.sockets[0].getsockname()[1]
        
        # Retrieve local address tuple
        # Let's map local interface address: e.g. 127.0.0.1 -> 127,0,0,1
        # If accessing externally, we map the host socket connection endpoint
        host_ip = self.writer.get_extra_info('sockname')[0]
        if host_ip == "::1" or host_ip == "0.0.0.0":
            host_ip = "127.0.0.1"
            
        ip_parts = host_ip.split('.')
        p1 = self.pasv_port >> 8
        p2 = self.pasv_port & 0xFF
        
        pasv_response = f"227 Entering Passive Mode ({','.join(ip_parts)},{p1},{p2}).\r\n"
        self.writer.write(pasv_response.encode('utf-8'))
        await self.writer.drain()
        logger.info(f"FTP Passive mode initiated on port {self.pasv_port}")

    async def _handle_data_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Invoked when the client initiates a connection to our passive port."""
        self.data_connection_future = (reader, writer)
        # Close passive server listener so we only handle a single transaction
        if self.pasv_server:
            self.pasv_server.close()

    async def _wait_for_data_connection(self) -> tuple:
        """Wait for client to establish the passive data channel."""
        for _ in range(30): # wait max 3 seconds
            if self.data_connection_future:
                return self.data_connection_future
            await asyncio.sleep(0.1)
        return None

    async def _handle_list(self):
        """Serves directory file lists over data channel."""
        self.writer.write(b"150 Here comes the directory listing.\r\n")
        await self.writer.drain()
        
        conn = await self._wait_for_data_connection()
        if not conn:
            self.writer.write(b"425 Can't open data connection.\r\n")
            await self.writer.drain()
            return
            
        d_reader, d_writer = conn
        try:
            # Send file listing details
            listing = (
                "-rw-r--r--    1 ftp      ftp          1024 Jul 23 12:00 backup.zip\r\n"
                "-rw-r--r--    1 ftp      ftp           512 Jul 23 12:05 credentials.txt\r\n"
                "-rw-r--r--    1 ftp      ftp         45812 Jul 23 12:10 admin_panel.php\r\n"
            )
            d_writer.write(listing.encode('utf-8'))
            await d_writer.drain()
            self.writer.write(b"226 Directory send OK.\r\n")
            await self.writer.drain()
        except Exception as e:
            logger.error(f"Error in FTP LIST data transfer: {e}")
            self.writer.write(b"451 Transfer aborted.\r\n")
            await self.writer.drain()
        finally:
            d_writer.close()
            self.data_connection_future = None

    async def _handle_retr(self, filename: str):
        """Sends fake files back to client."""
        self.writer.write(f"150 Opening BINARY mode data connection for {filename}.\r\n".encode('utf-8'))
        await self.writer.drain()
        
        conn = await self._wait_for_data_connection()
        if not conn:
            self.writer.write(b"425 Can't open data connection.\r\n")
            await self.writer.drain()
            return
            
        d_reader, d_writer = conn
        try:
            # Generate fake content depending on file requested
            decoy_content = f"SentinelAI Fake File Payload - {filename}\n".encode('utf-8')
            if "credentials" in filename.lower():
                decoy_content = (
                    "admin:adminpassword123\n"
                    "db_user:my_secret_database_pass_4492\n"
                    "support:helpdesk_secret_credentials_9981\n"
                ).encode('utf-8')
                
            d_writer.write(decoy_content)
            await d_writer.drain()
            self.writer.write(b"226 Transfer complete.\r\n")
            await self.writer.drain()
        except Exception as e:
            logger.error(f"Error in FTP RETR: {e}")
            self.writer.write(b"451 File transfer aborted.\r\n")
            await self.writer.drain()
        finally:
            d_writer.close()
            self.data_connection_future = None

    async def _handle_stor(self, filename: str):
        """Receives and quarantines uploaded file from client."""
        self.writer.write(f"150 Ok to send data.\r\n".encode('utf-8'))
        await self.writer.drain()
        
        conn = await self._wait_for_data_connection()
        if not conn:
            self.writer.write(b"425 Can't open data connection.\r\n")
            await self.writer.drain()
            return
            
        d_reader, d_writer = conn
        try:
            # Read full upload payload
            content = b""
            while True:
                chunk = await d_reader.read(4096)
                if not chunk:
                    break
                content += chunk
                
            # Quarantine the malware
            res = await honeypot_engine_instance.isolate_and_quarantine_file(filename, content)
            
            # Log upload event
            if res["success"]:
                await session_recorder_instance.log_file_upload(
                    self.session_id, res["filename"], res["size"], res["hashes"], res["quarantine_path"]
                )
                self.writer.write(b"226 File received and verified.\r\n")
            else:
                self.writer.write(b"451 Store failed.\r\n")
                
            await self.writer.drain()
        except Exception as e:
            logger.error(f"Error in FTP STOR: {e}")
            self.writer.write(b"451 Store aborted.\r\n")
            await self.writer.drain()
        finally:
            d_writer.close()
            self.data_connection_future = None

    async def _cleanup(self):
        """Cleanup control connection and passive ports."""
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass
            
        if self.pasv_server:
            self.pasv_server.close()
            
        if self.data_connection_future:
            _, d_writer = self.data_connection_future
            d_writer.close()
            
        await session_recorder_instance.close_session(self.session_id)

class FTPEmulator:
    def __init__(self):
        self.server = None

    async def start(self):
        """Starts the FTP listener on settings.PORT_FTP."""
        port = settings.PORT_FTP
        self.server = await asyncio.start_server(self.handle_connection, '0.0.0.0', port)
        logger.info(f"FTP Honeypot Emulator listening on port {port}...")

    async def stop(self):
        """Stops the FTP listener."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("FTP Honeypot Emulator stopped.")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Initial connection handler."""
        peer = writer.get_extra_info('peername')
        if not peer:
            writer.close()
            return
            
        ip, port = peer[0], peer[1]
        logger.info(f"Incoming FTP connection from {ip}:{port}")
        
        # Log simulated packet
        packet_analyzer_instance.log_simulated_packet(ip, settings.PORT_FTP, "TCP")
        
        # Start session recording
        session_id = await session_recorder_instance.create_session(ip, settings.PORT_FTP, "FTP")
        
        handler = FTPSessionHandler(reader, writer, session_id, ip)
        await handler.run()

ftp_emulator_instance = FTPEmulator()
