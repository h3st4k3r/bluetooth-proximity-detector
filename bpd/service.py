from __future__ import annotations

from dataclasses import dataclass

from .emitters import DeviceEmitter
from .receiver import DeviceReceiver
from .risk import RiskEngine


@dataclass
class AuditResult:
    total: int
    high_risk: int


class AuditService:
    def __init__(self, receiver: DeviceReceiver, emitters: list[DeviceEmitter], risk_engine: RiskEngine | None = None) -> None:
        self.receiver = receiver
        self.emitters = emitters
        self.risk_engine = risk_engine or RiskEngine()

    async def run_once(self) -> AuditResult:
        records = await self.receiver.receive()
        devices = list(records.values())

        for dev in devices:
            dev.findings = self.risk_engine.evaluate(dev)

        for emitter in self.emitters:
            emitter.emit(devices)

        high = sum(1 for d in devices if d.risk_label == "ALTO")
        return AuditResult(total=len(devices), high_risk=high)
