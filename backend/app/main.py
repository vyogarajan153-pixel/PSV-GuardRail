from datetime import datetime
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from .database import Base, engine, get_db
from .models import SecurityEvent, SecurityAlert, Incident, Endpoint, NetworkEvent, ThreatIndicator
from .schemas import AlertCreate, AlertUpdate, IncidentCreate, IncidentUpdate
from .seed import seed_database, NOW

Base.metadata.create_all(bind=engine)
from .database import SessionLocal
with SessionLocal() as seed_session: seed_database(seed_session)
app = FastAPI(title="PSV GuardRail API", version="1.1.0", description="Explainable security triage and guarded incident-response previews.")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False, allow_methods=["*"], allow_headers=["*"])

def find(db, model, item_id):
    obj = db.get(model, item_id)
    if not obj: raise HTTPException(404, "Resource not found")
    return obj

@app.get("/api/health")
def health(): return {"status":"healthy","environment":"portfolio simulation","timestamp":NOW}

@app.get("/api/events")
def events(search: str|None=None, severity: str|None=None, event_type: str|None=None, db: Session=Depends(get_db)):
    q=db.query(SecurityEvent)
    if severity: q=q.filter(SecurityEvent.severity==severity)
    if event_type: q=q.filter(SecurityEvent.event_type==event_type)
    if search: q=q.filter(SecurityEvent.description.ilike(f"%{search}%") | SecurityEvent.source_ip.ilike(f"%{search}%") | SecurityEvent.host.ilike(f"%{search}%"))
    return q.order_by(SecurityEvent.timestamp.desc()).all()
@app.get("/api/events/{item_id}")
def event(item_id:int,db:Session=Depends(get_db)): return find(db, SecurityEvent,item_id)

@app.get("/api/alerts")
def alerts(severity:str|None=None,status:str|None=None,alert_type:str|None=None,source_ip:str|None=None,db:Session=Depends(get_db)):
    q=db.query(SecurityAlert)
    for field,value in [(SecurityAlert.severity,severity),(SecurityAlert.status,status),(SecurityAlert.alert_type,alert_type),(SecurityAlert.source_ip,source_ip)]:
        if value: q=q.filter(field==value)
    return q.order_by(SecurityAlert.timestamp.desc()).all()
@app.get("/api/alerts/{item_id}")
def alert(item_id:int,db:Session=Depends(get_db)): return find(db,SecurityAlert,item_id)
@app.post("/api/alerts",status_code=201)
def create_alert(payload:AlertCreate,db:Session=Depends(get_db)):
    obj=SecurityAlert(timestamp=datetime.utcnow(),related_events="",**payload.model_dump()); db.add(obj); db.commit(); db.refresh(obj); return obj
@app.put("/api/alerts/{item_id}")
def update_alert(item_id:int,payload:AlertUpdate,db:Session=Depends(get_db)):
    obj=find(db,SecurityAlert,item_id)
    for k,v in payload.model_dump(exclude_none=True).items(): setattr(obj,k,v)
    db.commit(); db.refresh(obj); return obj

@app.get("/api/incidents")
def incidents(db:Session=Depends(get_db)): return db.query(Incident).order_by(Incident.last_updated.desc()).all()
@app.get("/api/incidents/{item_id}")
def incident(item_id:int,db:Session=Depends(get_db)): return find(db,Incident,item_id)
@app.post("/api/incidents",status_code=201)
def create_incident(payload:IncidentCreate,db:Session=Depends(get_db)):
    obj=Incident(status="New",created=datetime.utcnow(),last_updated=datetime.utcnow(),**payload.model_dump()); db.add(obj);db.commit();db.refresh(obj);return obj
@app.put("/api/incidents/{item_id}")
def update_incident(item_id:int,payload:IncidentUpdate,db:Session=Depends(get_db)):
    obj=find(db,Incident,item_id)
    for k,v in payload.model_dump(exclude_none=True).items(): setattr(obj,k,v)
    obj.last_updated=datetime.utcnow(); db.commit();db.refresh(obj);return obj

@app.get("/api/endpoints")
def endpoints(db:Session=Depends(get_db)): return db.query(Endpoint).order_by(Endpoint.last_seen.desc()).all()
@app.get("/api/endpoints/{item_id}")
def endpoint(item_id:int,db:Session=Depends(get_db)): return find(db,Endpoint,item_id)
@app.get("/api/network/events")
def network_events(db:Session=Depends(get_db)): return db.query(NetworkEvent).order_by(NetworkEvent.timestamp.desc()).all()
@app.get("/api/threat-intelligence")
def threat_intel(db:Session=Depends(get_db)): return db.query(ThreatIndicator).order_by(ThreatIndicator.last_seen.desc()).all()

@app.get("/api/dashboard/stats")
def dashboard_stats(db:Session=Depends(get_db)):
    alerts=db.query(SecurityAlert).all(); events=db.query(SecurityEvent).all(); incidents=db.query(Incident).all()
    return {"cards":{"total_events":len(events),"critical_alerts":sum(a.severity=="Critical" for a in alerts),"high_alerts":sum(a.severity=="High" for a in alerts),"open_incidents":sum(i.status not in ["Resolved","Closed"] for i in incidents),"resolved_incidents":sum(i.status=="Resolved" for i in incidents),"suspicious_ips":len(set(a.source_ip for a in alerts if a.severity in ["Critical","High"])),"endpoints":db.query(Endpoint).count(),"failed_logins":sum("Failed login" in e.description for e in events)},"events_over_time":[{"time":f"{h:02d}:00","events":16+(h*7)%33,"alerts":2+(h*3)%8} for h in range(0,24,3)],"severity":[{"name":s,"value":sum(a.severity==s for a in alerts)} for s in ["Critical","High","Medium","Low","Informational"]],"categories":[{"name":c,"value":sum(e.category==c for e in events)} for c in ["Authentication","Network","Endpoint","Malware","Firewall"]],"incident_status":[{"name":s,"value":sum(i.status==s for i in incidents)} for s in ["New","Investigating","Contained","Resolved","Closed"]],"top_ips":[{"ip":ip,"event_count":sum(e.source_ip==ip for e in events),"threat_score":94-i*8,"country":["External / Unknown","External / Unknown","Internal","External / Unknown"][i%4],"status":"Blocked" if i<2 else "Monitoring"} for i,ip in enumerate(["185.199.108.153","45.146.164.110","91.240.118.72","10.20.5.14"])]}
@app.get("/api/reports/summary")
def reports(db:Session=Depends(get_db)):
    return {"resolution_rate":70,"top_endpoints":[{"name":"ENG-WS-03","value":9},{"name":"DC-01","value":7},{"name":"FIN-WS-09","value":5},{"name":"VPN-01","value":4}],"auth_failures":[{"day":d,"failures":8+(i*5)%18} for i,d in enumerate(["Mon","Tue","Wed","Thu","Fri","Sat","Sun"])]}
