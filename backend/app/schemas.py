from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional

class Config: from_attributes = True

class AlertCreate(BaseModel):
    severity: str = Field(pattern="^(Critical|High|Medium|Low|Informational)$")
    alert_type: str
    source_ip: str
    destination: str
    user: str = "System"
    host: str = "N/A"
    status: str = "New"
    description: str
    detection_reason: str
    recommended_response: str

class AlertUpdate(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    description: Optional[str] = None

class IncidentCreate(BaseModel):
    title: str
    severity: str = Field(pattern="^(Critical|High|Medium|Low|Informational)$")
    assigned_analyst: str = "Unassigned"
    summary: str = "Created from SOC dashboard"

class IncidentUpdate(BaseModel):
    severity: Optional[str] = None
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    summary: Optional[str] = None
