from datetime import datetime, timedelta
from random import Random
from sqlalchemy.orm import Session
from .models import SecurityEvent, SecurityAlert, Incident, Endpoint, NetworkEvent, ThreatIndicator

NOW = datetime(2026, 8, 29, 14, 30)
rng = Random(42)
SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]

def detection_rules(events):
    """Small, transparent portfolio detection simulation; never use for live monitoring."""
    alerts = []
    failed_by_ip = {}
    for event in events:
        if event.event_type == "Authentication" and "failed" in event.description.lower():
            failed_by_ip.setdefault(event.source_ip, []).append(event)
        if event.event_type == "Endpoint" and "powershell" in event.description.lower():
            alerts.append(("High", "Suspicious PowerShell Activity", event, "Encoded PowerShell command observed on endpoint"))
        if event.event_type == "Malware":
            alerts.append(("Critical", "Malware Detection", event, "Endpoint security agent reported malware-like behavior"))
    for ip, matching in failed_by_ip.items():
        if len(matching) >= 3:
            alerts.append(("High", "Possible Brute Force Attack", matching[0], f"{len(matching)} failed logins from {ip}"))
    return alerts

def seed_database(db: Session):
    if db.query(SecurityEvent).count(): return
    event_types = ["Authentication", "Network", "Endpoint", "Malware", "Firewall", "VPN", "Privilege Escalation", "Access Control"]
    hosts = [f"WS-{i:02d}" for i in range(1, 13)] + ["DC-01", "FILE-01", "WEB-01", "VPN-01"]
    users = ["a.hassan", "m.salem", "j.rahman", "svc_backup", "admin.ops", "k.nasser"]
    source_ips = ["10.20.5.14", "10.20.8.22", "192.168.40.53", "185.199.108.153", "45.146.164.110", "91.240.118.72"]
    descriptions = {
        "Authentication": ["Failed login attempt for account", "Successful interactive sign-in", "MFA challenge completed", "Multiple failed login attempts detected"],
        "Network": ["Unusual outbound traffic pattern detected", "Connection to external service observed", "DNS query matched suspicious domain"],
        "Endpoint": ["PowerShell executed with encoded command", "Endpoint agent policy check completed", "Suspicious process spawned from Office document"],
        "Malware": ["Malware signature detected and quarantined", "Potentially unwanted application blocked"],
        "Firewall": ["Firewall blocked connection to unusual port", "Inbound policy denied connection"],
        "VPN": ["VPN authentication from unusual location", "VPN session established"],
        "Privilege Escalation": ["Privileged group membership modified", "Administrative token requested"],
        "Access Control": ["Access denied to restricted share", "Sensitive file access recorded"]
    }
    events = []
    for i in range(124):
        typ = event_types[i % len(event_types)]
        ip = source_ips[i % len(source_ips)]
        desc = descriptions[typ][i % len(descriptions[typ])]
        if i in range(8, 16): typ, ip, desc = "Authentication", "185.199.108.153", "Failed login attempt for account"
        event = SecurityEvent(timestamp=NOW-timedelta(minutes=i*19), event_type=typ, severity=SEVERITIES[(i*3)%5], source="Microsoft Defender" if typ in ["Endpoint", "Malware"] else "SOC Sensor", source_ip=ip, username=users[i%len(users)], host=hosts[i%len(hosts)], description=f"{desc} {users[i%len(users)]}.", category=typ)
        events.append(event)
    db.add_all(events); db.flush()
    detected = detection_rules(events)
    alert_types = ["Multiple Failed Login Attempts", "Suspicious PowerShell Activity", "Possible Brute Force Attack", "Malware Detection", "Unusual Outbound Traffic", "Privileged Account Login Anomaly", "Suspicious VPN Authentication", "Unusual Port Access"]
    alerts = []
    for i in range(34):
        e = events[(i*7) % len(events)]
        typ = alert_types[i % len(alert_types)]
        severity = ["Critical", "High", "High", "Critical", "Medium", "High", "Medium", "Low"][i % 8]
        reason = f"Correlation rule matched fictional {typ.lower()} telemetry."
        alerts.append(SecurityAlert(timestamp=e.timestamp+timedelta(minutes=2), severity=severity, alert_type=typ, source_ip=e.source_ip, destination=e.host, user=e.username, host=e.host, status=["New", "Investigating", "Contained", "Resolved"][i%4], description=f"Simulated alert: {typ} involving {e.host}.", detection_reason=reason, recommended_response="Validate the activity, review related events, and contain the affected asset if malicious.", related_events=",".join(str(x.id) for x in events[i:i+3])))
    db.add_all(alerts)
    incident_titles = ["Multiple Failed Login Attempts", "Suspicious PowerShell Activity", "Possible Brute Force Attack", "Malware Detection", "Unusual Outbound Traffic", "Privileged Account Login Anomaly", "Suspicious VPN Authentication", "Unusual RDP Connection", "Suspicious DNS Activity", "Unauthorized Access Attempt"]
    db.add_all([Incident(title=t, severity=["High","High","Critical","Critical","Medium","High","Medium","Medium","Low","High"][i], status=["New","Investigating","Contained","Resolved","Closed"][i%5], assigned_analyst=["Waleed Alharbi","Maya Khan","Omar Aziz","Waleed Alharbi"][i%4], created=NOW-timedelta(hours=10+i*6), last_updated=NOW-timedelta(hours=i), summary=f"Fictional portfolio incident for {t.lower()}.") for i,t in enumerate(incident_titles)])
    db.add_all([Endpoint(hostname=f"{['FIN','ENG','HR','OPS'][i%4]}-WS-{i+1:02d}", ip_address=f"10.20.{10+i//8}.{20+i}", operating_system="Windows 11 Enterprise" if i%3 else "Ubuntu 22.04 LTS", status=["Online","Online","Warning","Offline","Isolated"][i%5], risk_level=["Low","Medium","High","Critical"][i%4], last_seen=NOW-timedelta(minutes=i*13), security_agent="Defender for Endpoint", open_alerts=i%5) for i in range(20)])
    protocols = ["TCP","UDP","HTTPS","DNS","SSH","RDP"]
    db.add_all([NetworkEvent(timestamp=NOW-timedelta(minutes=i*11), source_ip=source_ips[i%len(source_ips)], destination_ip=f"172.16.{i%8}.{10+i}", protocol=protocols[i%6], port=[443,53,22,3389,8080,445][i%6], action=["Allowed","Blocked","Flagged"][i%3], event_count=8+i*3, risk_score=20+(i*13)%78) for i in range(50)])
    iocs = ["185.199.108.153","45.146.164.110","91.240.118.72","login-update-security.example","cdn-auth-check.example","a3f5c88e9b...","e1d4b7c2aa...","malware-dropper.example"]
    db.add_all([ThreatIndicator(indicator=iocs[i%len(iocs)] if i<8 else f"198.51.100.{20+i}", indicator_type=["IP Address","Domain","Hash"][i%3], threat_level=["Critical","High","Medium","Low"][i%4], confidence=58+(i*7)%40, first_seen=NOW-timedelta(days=30+i), last_seen=NOW-timedelta(hours=i*4), status=["Active","Monitoring","Blocked"][i%3]) for i in range(20)])
    db.commit()
