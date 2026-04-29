from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class RiskFinding:
    title: str
    severity: str
    confidence: float
    rationale: str
    recommendation: str


@dataclass
class DeviceRecord:
    address: str
    display_name: str
    local_name: str | None
    manufacturer_ids: list[int] = field(default_factory=list)
    manufacturer_names: list[str] = field(default_factory=list)
    service_uuids: list[str] = field(default_factory=list)
    service_labels: list[str] = field(default_factory=list)
    service_data_uuids: list[str] = field(default_factory=list)
    tx_power: int | None = None
    rssi_raw: int = -127
    rssi_ema: float = -127.0
    distance_m: float = 0.0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    hits: int = 1
    probable_type: str = "desconocido"
    address_privacy_hint: str = "unknown"
    findings: list[RiskFinding] = field(default_factory=list)
    active_probe: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> int:
        score = 0
        for finding in self.findings:
            sev = finding.severity
            if sev == "critical":
                score += 40
            elif sev == "high":
                score += 25
            elif sev == "medium":
                score += 15
            elif sev == "low":
                score += 8
            else:
                score += 3
            score += int(5 * finding.confidence)
        return min(100, score)

    @property
    def risk_label(self) -> str:
        severities = {finding.severity for finding in self.findings}
        if "critical" in severities or "high" in severities:
            return "HIGH"
        if "medium" in severities:
            return "MEDIUM"
        if "low" in severities:
            return "LOW"

        score = self.risk_score
        if score >= 70:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "N/A"

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "display_name": self.display_name,
            "local_name": self.local_name,
            "manufacturer_ids": self.manufacturer_ids,
            "manufacturer_names": self.manufacturer_names,
            "service_uuids": self.service_uuids,
            "service_labels": self.service_labels,
            "service_data_uuids": self.service_data_uuids,
            "tx_power": self.tx_power,
            "rssi_raw": self.rssi_raw,
            "rssi_ema": round(self.rssi_ema, 2),
            "distance_m": round(self.distance_m, 2),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "hits": self.hits,
            "probable_type": self.probable_type,
            "address_privacy_hint": self.address_privacy_hint,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "active_probe": self.active_probe,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "rationale": f.rationale,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
        }
