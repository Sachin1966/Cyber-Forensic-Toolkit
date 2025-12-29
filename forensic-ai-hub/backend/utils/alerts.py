import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def trigger_high_risk_alert(result, user_context):
    """
    Triggers an alert if the threat score is high.
    """
    threat_score = result.get('threatScore', 0)
    risk_label = result.get('result', 'unknown')
    
    if threat_score >= 80 or risk_label == 'danger':
        print(f"🚨 HIGH RISK DETECTED [{datetime.now()}]: {result.get('type', 'Unknown Type')} - Score: {threat_score}")
        
        user_email = user_context.get('email')
        if not user_email:
            print("No user email provided for alert.")
            return

        # Send Email
        send_email(user_email, result)

def send_email(to_email, data):
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', '587'))
    smtp_user = os.getenv('SMTP_USER')
    smtp_pass = os.getenv('SMTP_PASS')
    
    if not smtp_user or not smtp_pass:
        print("⚠️ SMTP credentials not set. Skipping email alert.")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = smtp_user
        msg['To'] = to_email
        msg['Subject'] = f"🚨 High Security Alert: {data.get('type', 'Unknown').upper()} Detected"

        body = f"""
        <h1>High Security Threat Detected</h1>
        <p>A high-risk threat was detected by the Cyber Forensic AI Toolkit.</p>
        <ul>
            <li><strong>Type:</strong> {data.get('type')}</li>
            <li><strong>Threat Score:</strong> {data.get('threatScore')}</li>
            <li><strong>Status:</strong> {data.get('result')}</li>
            <li><strong>Filename/URL:</strong> {data.get('name') or data.get('filename') or data.get('url')}</li>
            <li><strong>Time:</strong> {datetime.now()}</li>
        </ul>
        <p>Please investigate immediately.</p>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, to_email, msg.as_string())
        server.quit()
        print(f"✅ Alert email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send alert email: {e}")
