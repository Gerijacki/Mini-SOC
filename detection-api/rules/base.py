from abc import ABC, abstractmethod

from elasticsearch import Elasticsearch

from models import Alert, AlertSeverity


class DetectionRule(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def detect(self, client: Elasticsearch) -> list[Alert]:
        ...

    def get_severity(self, event_count: int) -> AlertSeverity:
        if event_count >= 20:
            return AlertSeverity.critical
        if event_count >= 10:
            return AlertSeverity.high
        if event_count >= 5:
            return AlertSeverity.medium
        return AlertSeverity.low
