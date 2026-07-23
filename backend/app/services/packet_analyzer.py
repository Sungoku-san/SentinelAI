import asyncio
import threading
from backend.app.utils.helpers import get_logger

logger = get_logger("packet_analyzer")

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy is not installed or not available. Packet analyzer will run in fallback simulation mode.")

class PacketAnalyzer:
    def __init__(self):
        self.running = False
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "ip_counts": {},
            "port_counts": {}
        }
        self.thread = None

    def start_capture(self, interface: str = None):
        """Starts packet capture in a background thread if scapy is available."""
        if self.running:
            return
            
        self.running = True
        if SCAPY_AVAILABLE:
            self.thread = threading.Thread(target=self._run_sniff, args=(interface,), daemon=True)
            self.thread.start()
            logger.info("Scapy packet sniffer started in background thread.")
        else:
            logger.info("Packet analyzer simulation mode active.")

    def stop_capture(self):
        """Stops packet capture."""
        self.running = False
        logger.info("Packet sniffer stopped.")

    def get_stats(self) -> dict:
        """Returns packet collection statistics."""
        return self.stats

    def _run_sniff(self, interface):
        """Wrapper method for Scapy sniffing."""
        try:
            # Filters traffic directed to our honeypot ports
            # Standard user interfaces or loopback
            filter_str = "tcp port 2222 or tcp port 8080 or tcp port 2121 or tcp port 2323"
            
            # Keep standard arguments simple
            sniff(
                prn=self._process_packet,
                filter=filter_str,
                store=0,
                stop_filter=lambda x: not self.running,
                iface=interface
            )
        except Exception as e:
            logger.error(f"Error in Scapy sniffing: {e}. Reverting to simulation statistics.")

    def _process_packet(self, packet):
        """Callback to extract details from each intercepted packet."""
        try:
            self.stats["total_packets"] += 1
            
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                self.stats["ip_counts"][ip_src] = self.stats["ip_counts"].get(ip_src, 0) + 1
                
            if packet.haslayer(TCP):
                self.stats["tcp_packets"] += 1
                dport = packet[TCP].dport
                self.stats["port_counts"][dport] = self.stats["port_counts"].get(dport, 0) + 1
                
            elif packet.haslayer(UDP):
                self.stats["udp_packets"] += 1
                dport = packet[UDP].dport
                self.stats["port_counts"][dport] = self.stats["port_counts"].get(dport, 0) + 1
        except Exception as e:
            pass

    def log_simulated_packet(self, ip_src: str, port: int, protocol: str = "TCP"):
        """Enables protocol listeners to register packet stats as a fallback."""
        self.stats["total_packets"] += 1
        self.stats["ip_counts"][ip_src] = self.stats["ip_counts"].get(ip_src, 0) + 1
        self.stats["port_counts"][port] = self.stats["port_counts"].get(port, 0) + 1
        
        if protocol == "TCP":
            self.stats["tcp_packets"] += 1
        elif protocol == "UDP":
            self.stats["udp_packets"] += 1

packet_analyzer_instance = PacketAnalyzer()
