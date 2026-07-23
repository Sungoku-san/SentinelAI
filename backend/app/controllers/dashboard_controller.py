from backend.app.config.settings import settings
from backend.app.database.mongodb import get_database
from backend.app.models.schemas import DashboardStatsResponse
from backend.app.services.packet_analyzer import packet_analyzer_instance
from backend.app.utils.helpers import get_logger

logger = get_logger("dashboard_controller")

class DashboardController:
    async def get_dashboard_stats(self) -> dict:
        """Aggregates metrics and distributions from MongoDB for dashboard display."""
        db = get_database()
        
        # Zero baseline fallbacks if MongoDB connection fails or collections are empty
        stats = {
            "total_sessions": 0,
            "total_attacks": 0,
            "critical_alerts": 0,
            "unique_ips": 0,
            "protocol_distribution": {"SSH": 0, "HTTP": 0, "FTP": 0, "Telnet": 0},
            "threat_level_distribution": {"Low": 0, "Medium": 0, "High": 0, "Critical": 0},
            "top_ips": []
        }
        
        if db is None:
            return stats
            
        try:
            # 1. Counts
            stats["total_sessions"] = await db.sessions.count_documents({})
            stats["total_attacks"] = await db.attack_logs.count_documents({})
            stats["critical_alerts"] = await db.sessions.count_documents({"threat_level": "Critical"})
            
            # 2. Unique IPs using MongoDB aggregation
            ip_pipeline = [{"$group": {"_id": "$ip_address"}}, {"$count": "count"}]
            ip_res = await db.sessions.aggregate(ip_pipeline).to_list(length=1)
            stats["unique_ips"] = ip_res[0]["count"] if ip_res else 0
            
            # 3. Protocol Distribution
            protocols = ["SSH", "HTTP", "FTP", "Telnet"]
            for proto in protocols:
                stats["protocol_distribution"][proto] = await db.sessions.count_documents({"protocol": proto})
                
            # 4. Threat Level Distribution
            levels = ["Low", "Medium", "High", "Critical"]
            for lvl in levels:
                stats["threat_level_distribution"][lvl] = await db.sessions.count_documents({"threat_level": lvl})
                
            # 5. Top Attacking IPs
            top_pipeline = [
                {"$group": {
                    "_id": "$ip_address",
                    "attack_count": {"$sum": 1},
                    "max_score": {"$max": "$threat_score"},
                    "protocols": {"$addToSet": "$protocol"},
                    "country": {"$first": "$geo_location.countryCode"}
                }},
                {"$sort": {"max_score": -1, "attack_count": -1}},
                {"$limit": 10}
            ]
            cursor = db.sessions.aggregate(top_pipeline)
            top_ips = []
            async for doc in cursor:
                top_ips.append({
                    "ip_address": doc["_id"],
                    "attack_count": doc["attack_count"],
                    "max_score": doc["max_score"],
                    "protocols": doc["protocols"],
                    "country": doc["country"] or "UN"
                })
            stats["top_ips"] = top_ips
            
        except Exception as e:
            logger.error(f"Error querying dashboard aggregations: {e}")
            
        return stats

    def get_system_status(self) -> dict:
        """Retrieves statuses of honeypot emulators and network statistics."""
        # Check active instances import state to verify running status
        from backend.app.services.ssh_emulator import ssh_emulator_instance
        from backend.app.services.http_emulator import http_emulator_instance
        from backend.app.services.ftp_emulator import ftp_emulator_instance
        from backend.app.services.telnet_emulator import telnet_emulator_instance
        
        return {
            "ssh_port": settings.PORT_SSH,
            "http_port": settings.PORT_HTTP,
            "ftp_port": settings.PORT_FTP,
            "telnet_port": settings.PORT_TELNET,
            "ssh_running": ssh_emulator_instance.running,
            "http_running": http_emulator_instance.server is not None and not http_emulator_instance.server.should_exit,
            "ftp_running": ftp_emulator_instance.server is not None,
            "telnet_running": telnet_emulator_instance.server is not None,
            "packet_stats": packet_analyzer_instance.get_stats()
        }

dashboard_controller_instance = DashboardController()
