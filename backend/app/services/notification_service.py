import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import httpx
from backend.app.config.settings import settings
from backend.app.utils.helpers import get_logger

logger = get_logger("notification_service")

class NotificationService:
    async def send_alert(self, session_data: dict):
        """Dispatches email and telegram alerts for high/critical security threats."""
        threat_level = session_data.get("threat_level", "Unknown")
        threat_score = session_data.get("threat_score", 0.0)
        ip = session_data.get("ip_address", "Unknown")
        protocol = session_data.get("protocol", "Unknown")
        classification = session_data.get("ai_classification", "Unknown")
        explanation = session_data.get("ai_explanation", "")
        
        # Build alert message
        alert_title = f"⚠️ [SentinelAI] {threat_level.upper()} Security Threat Alert!"
        alert_body = (
            f"SentinelAI Honeypot has detected a severe security event.\n\n"
            f"Source IP: {ip}\n"
            f"Protocol Target: {protocol}\n"
            f"Threat Score: {threat_score:.1f}/100 ({threat_level} Severity)\n"
            f"AI Classification: {classification}\n"
            f"Details: {explanation}\n\n"
            f"Log Time: {session_data.get('start_time')}\n"
        )
        
        logger.info(f"Triggered Alert: {alert_title}\n{alert_body}")
        
        # 1. Dispatch Telegram Alert
        if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
            await self._send_telegram(alert_title, alert_body)
            
        # 2. Dispatch SMTP Email Alert
        if settings.SMTP_USERNAME and settings.ALERT_EMAIL_RECIPIENT:
            await self._send_email(alert_title, alert_body)

    async def _send_telegram(self, title: str, body: str):
        """Sends markdown messages to configured Telegram chats."""
        message = f"*{title}*\n\n{body}"
        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": settings.TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(url, json=payload)
                if response.status_code == 200:
                    logger.info("Telegram notification successfully sent.")
                else:
                    logger.error(f"Failed to send Telegram notification: {response.text}")
        except Exception as e:
            logger.error(f"Error dispatching Telegram alert: {e}")

    async def _send_email(self, title: str, body: str):
        """Sends secure SMTP email alerts."""
        msg = MIMEMultipart()
        msg['From'] = settings.SMTP_USERNAME
        msg['To'] = settings.ALERT_EMAIL_RECIPIENT
        msg['Subject'] = title
        msg.attach(MIMEText(body, 'plain'))
        
        # Async wrapping of blocking smtplib operations
        try:
            import asyncio
            await asyncio.to_thread(self._smtp_send_sync, msg)
            logger.info("Email notification successfully sent.")
        except Exception as e:
            logger.error(f"Error dispatching SMTP email alert: {e}")

    def _smtp_send_sync(self, msg: MIMEMultipart):
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.send_message(msg)

notification_service_instance = NotificationService()
