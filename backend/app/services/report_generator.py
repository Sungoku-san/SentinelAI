import os
import csv
import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from backend.app.config.settings import settings
from backend.app.utils.helpers import get_logger

logger = get_logger("report_generator")

class ReportGenerator:
    def generate_pdf_report(self, sessions: list, filename: str) -> str:
        """Generates a professional executive security PDF threat intelligence report."""
        pdf_path = os.path.join(settings.REPORT_DIR, filename)
        
        try:
            doc = SimpleDocTemplate(
                pdf_path,
                pagesize=letter,
                rightMargin=30,
                leftMargin=30,
                topMargin=30,
                bottomMargin=30
            )
            
            styles = getSampleStyleSheet()
            
            # Custom Styles
            title_style = ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontSize=22,
                textColor=colors.HexColor('#1E293B'),
                spaceAfter=15,
                alignment=0
            )
            
            section_style = ParagraphStyle(
                'SectionHeader',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#0F172A'),
                spaceBefore=12,
                spaceAfter=8,
                borderWidth=1,
                borderColor=colors.HexColor('#E2E8F0')
            )
            
            body_style = ParagraphStyle(
                'ReportBody',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.HexColor('#334155'),
                spaceAfter=6
            )
            
            story = []
            
            # Title block
            story.append(Paragraph("SentinelAI Threat Intelligence Summary", title_style))
            story.append(Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
            story.append(Paragraph(f"Analyzed Datasets: {len(sessions)} Active Attacker Sessions recorded.", body_style))
            story.append(Spacer(1, 15))
            
            # Executive Metrics
            critical_count = sum(1 for s in sessions if s.get("threat_level") == "Critical")
            high_count = sum(1 for s in sessions if s.get("threat_level") == "High")
            med_count = sum(1 for s in sessions if s.get("threat_level") == "Medium")
            low_count = sum(1 for s in sessions if s.get("threat_level") == "Low")
            
            story.append(Paragraph("Executive Summary metrics:", section_style))
            summary_text = (
                f"During this threat evaluation window, SentinelAI captured connection probes across multiple virtualized emulators. "
                f"Among the sessions, {critical_count} threat vectors were classified as <b>Critical</b> and {high_count} as <b>High</b>. "
                f"Attackers demonstrated credential brute-forcing, file transfers, and dynamic payload execution."
            )
            story.append(Paragraph(summary_text, body_style))
            story.append(Spacer(1, 10))
            
            # Metrics table
            metrics_data = [
                ['Threat Level', 'Occurrences', 'Risk Classification'],
                [Paragraph('<b>Critical</b>', body_style), str(critical_count), 'High Mitigation Priority'],
                [Paragraph('<b>High</b>', body_style), str(high_count), 'Medium Mitigation Priority'],
                [Paragraph('<b>Medium</b>', body_style), str(med_count), 'Monitoring Required'],
                [Paragraph('<b>Low</b>', body_style), str(low_count), 'Background Probes']
            ]
            
            t_metrics = Table(metrics_data, colWidths=[120, 100, 200])
            t_metrics.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0F172A')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('BOTTOMPADDING', (0,0), (-1,0), 6),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F8FAFC'), colors.white])
            ]))
            story.append(t_metrics)
            story.append(Spacer(1, 15))
            
            # Sessions listing
            story.append(Paragraph("Attacking Host Summary (Top Sessions)", section_style))
            
            sessions_data = [['Timestamp', 'IP Address', 'Protocol', 'Threat Level', 'AI Classification', 'Score']]
            
            for s in sessions[:15]: # Limit to top 15 records in PDF
                ts = s.get("start_time")
                ts_str = ts.strftime("%m-%d %H:%M") if isinstance(ts, datetime.datetime) else str(ts)[:11]
                
                sessions_data.append([
                    ts_str,
                    s.get("ip_address", "Unknown"),
                    s.get("protocol", "Unknown"),
                    s.get("threat_level", "Low"),
                    s.get("ai_classification", "N/A"),
                    f"{s.get('threat_score', 0):.1f}"
                ])
                
            t_sess = Table(sessions_data, colWidths=[80, 90, 60, 80, 110, 50])
            t_sess.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('BOTTOMPADDING', (0,0), (-1,0), 5),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#F1F5F9'), colors.white])
            ]))
            
            story.append(t_sess)
            
            doc.build(story)
            logger.info(f"PDF report successfully created at {pdf_path}")
            return pdf_path
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise e

    def generate_csv_report(self, sessions: list, filename: str) -> str:
        """Generates raw threat session details to CSV format."""
        csv_path = os.path.join(settings.REPORT_DIR, filename)
        
        try:
            with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Session ID", "IP Address", "Protocol", "Port", 
                    "Start Time", "End Time", "Threat Score", "Threat Level", 
                    "AI Classification", "AI Explanation", "Login Attempts", 
                    "Commands Executed", "Files Uploaded"
                ])
                
                for s in sessions:
                    feats = s.get("features", {})
                    writer.writerow([
                        s.get("session_id"),
                        s.get("ip_address"),
                        s.get("protocol"),
                        s.get("port"),
                        s.get("start_time"),
                        s.get("end_time"),
                        s.get("threat_score"),
                        s.get("threat_level"),
                        s.get("ai_classification"),
                        s.get("ai_explanation"),
                        feats.get("login_attempts", 0),
                        feats.get("commands_count", 0),
                        feats.get("malware_uploaded", 0)
                    ])
                    
            logger.info(f"CSV report successfully created at {csv_path}")
            return csv_path
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")
            raise e

report_generator_instance = ReportGenerator()
