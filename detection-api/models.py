from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Alert(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")
    rule_name: str
    source_ip: str
    severity: AlertSeverity
    details: dict[str, Any] = {}
    response_taken: str = "pending"
    event_count: int = 0

    def to_es_doc(self) -> dict:
        return {
            "@timestamp": self.timestamp,
            "rule_name": self.rule_name,
            "source_ip": self.source_ip,
            "severity": self.severity.value,
            "details": self.details,
            "response_taken": self.response_taken,
            "event_count": self.event_count,
        }


class HealthResponse(BaseModel):
    status: str
    es_connected: bool
    rules_loaded: int
    last_poll: str | None = None
    alerts_generated: int = 0
