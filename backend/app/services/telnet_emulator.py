import asyncio
from backend.app.config.settings import settings
from backend.app.services.honeypot_engine import honeypot_engine_instance
from backend.app.services.session_recorder import session_recorder_instance
from backend.app.services.packet_analyzer import packet_analyzer_instance
from backend.app.utils.helpers import get_logger

logger = get_logger("telnet_emulator")

class TelnetEmulator:
    def __init__(self):
        self.server = None

    async def start(self):
        """Starts the Telnet socket listener."""
        port = settings.PORT_TELNET
        self.server = await asyncio.start_server(self.handle_connection, '0.0.0.0', port)
        logger.info(f"Telnet Honeypot Emulator listening on port {port}...")

    async def stop(self):
        """Stops the Telnet socket listener."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Telnet Honeypot Emulator stopped.")

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handles incoming Telnet connection lifecycle."""
        peer = writer.get_extra_info('peername')
        if not peer:
            writer.close()
            return
            
        ip, port = peer[0], peer[1]
        logger.info(f"Incoming Telnet connection from {ip}:{port}")
        
        # Register simulated packet in analyzer
        packet_analyzer_instance.log_simulated_packet(ip, settings.PORT_TELNET, "TCP")
        
        # Create session in recorder
        session_id = await session_recorder_instance.create_session(ip, settings.PORT_TELNET, "Telnet")
        
        try:
            # Cisco banner style
            writer.write(b"\r\n\r\nUser Access Verification\r\n\r\n")
            await writer.drain()
            
            # Step 1: Login Loop
            authenticated = False
            username = ""
            password = ""
            
            for attempt in range(5):
                # Adaptive delay
                delay = await honeypot_engine_instance.get_connection_delay(ip)
                if delay > 0:
                    await asyncio.sleep(delay)
                    
                writer.write(b"Username: ")
                await writer.drain()
                
                # Read username
                user_data = await reader.readline()
                if not user_data:
                    break
                username = user_data.decode('utf-8', errors='ignore').strip()
                
                writer.write(b"Password: ")
                await writer.drain()
                
                # Telnet hides password usually, but standard text reading is sufficient for capture
                pass_data = await reader.readline()
                if not pass_data:
                    break
                password = pass_data.decode('utf-8', errors='ignore').strip()
                
                # Log credentials attempt
                await session_recorder_instance.log_credential_attempt(session_id, username, password, success=False)
                honeypot_engine_instance.register_login_failure(ip)
                
                # Check adaptive engine to see if we should trap them in the fake sandbox shell
                if honeypot_engine_instance.should_accept_brute_force(ip) or (username == "admin" and password == "admin"):
                    authenticated = True
                    break
                else:
                    writer.write(b"\r\n% Login invalid\r\n\r\n")
                    await writer.drain()
            
            if not authenticated:
                writer.write(b"\r\nConnection closed by foreign host.\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                await session_recorder_instance.close_session(session_id)
                return

            # Step 2: Interactive CLI Loop
            writer.write(b"\r\nSwitch# ")
            await writer.drain()
            
            while True:
                line_data = await reader.readline()
                if not line_data:
                    break
                    
                command = line_data.decode('utf-8', errors='ignore').strip()
                if not command:
                    writer.write(b"Switch# ")
                    await writer.drain()
                    continue
                    
                cmd_lower = command.lower()
                response = ""
                
                if cmd_lower in ("exit", "quit"):
                    writer.write(b"\r\nGoodbye.\r\n")
                    await writer.drain()
                    break
                elif cmd_lower in ("help", "?"):
                    response = (
                        "\r\nExec Commands:\r\n"
                        "  clear        Reset functions\r\n"
                        "  disable      Turn off privileged commands\r\n"
                        "  enable       Turn on privileged commands\r\n"
                        "  exit         Exit from the EXEC\r\n"
                        "  help         Description of the interactive help system\r\n"
                        "  show         Show running system information\r\n"
                    )
                elif cmd_lower == "enable":
                    response = "\r\nPassword: \r\n% Access denied\r\n"
                elif cmd_lower.startswith("show ip interface brief"):
                    response = (
                        "\r\nInterface              IP-Address      OK? Method Status                Protocol\r\n"
                        "Vlan1                  192.168.1.1     YES manual up                    up      \r\n"
                        "FastEthernet0/1        unassigned      YES unset  down                  down    \r\n"
                        "FastEthernet0/2        unassigned      YES unset  up                    up      \r\n"
                    )
                elif cmd_lower.startswith("show version"):
                    response = (
                        "\r\nCisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 12.2(55)SE7, RELEASE SOFTWARE (fc1)\r\n"
                        "Technical Support: http://www.cisco.com/techsupport\r\n"
                        "Copyright (c) 1986-2013 by Cisco Systems, Inc.\r\n"
                        "Compiled Thu 31-Jan-13 12:47 by prod_rel_team\r\n"
                        "System image file is \"flash:/c2960-lanbasek9-mz.122-55.SE7.bin\"\r\n"
                    )
                elif cmd_lower == "whoami":
                    response = "\r\nadmin\r\n"
                else:
                    response = f"\r\n% Unrecognized command: '{command}'\r\n"
                    
                # Log command
                await session_recorder_instance.log_command_execution(session_id, command, response)
                
                # Send response back
                writer.write(response.encode('utf-8'))
                writer.write(b"Switch# ")
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Error in Telnet connection handler: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            await session_recorder_instance.close_session(session_id)

telnet_emulator_instance = TelnetEmulator()
