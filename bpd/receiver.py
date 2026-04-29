from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from .active_audit import ActiveGattAuditor
from .enrichment import (
    COMPANY_ID_MAP,
    address_privacy_hint,
    estimate_distance,
    infer_device_type,
    resolve_service_labels,
)
from .models import DeviceRecord

try:
    from bleak import BleakScanner
except Exception:  # pragma: no cover
    BleakScanner = None


class DeviceReceiver(ABC):
    @abstractmethod
    async def receive(self) -> dict[str, DeviceRecord]:
        raise NotImplementedError


class BleDeviceReceiver(DeviceReceiver):
    def __init__(
        self,
        scan_seconds: float,
        rssi_ref: int,
        path_loss_exponent: float,
        ema_alpha: float,
        company_map: dict[int, str] | None = None,
        active_probe: bool = False,
        probe_limit: int = 3,
        probe_timeout: float = 7.0,
        include_serial: bool = False,
        deep_audit: bool = False,
        read_descriptors: bool = False,
        max_read_bytes: int = 96,
        target_filters: list[str] | None = None,
    ) -> None:
        self.scan_seconds = scan_seconds
        self.rssi_ref = rssi_ref
        self.path_loss_exponent = path_loss_exponent
        self.ema_alpha = ema_alpha
        self.active_probe = active_probe
        self.probe_limit = probe_limit
        self.probe_timeout = probe_timeout
        self.include_serial = include_serial
        self.deep_audit = deep_audit
        self.read_descriptors = read_descriptors
        self.max_read_bytes = max_read_bytes
        self.target_filters = [target.lower() for target in (target_filters or [])]
        self.company_map = {**COMPANY_ID_MAP, **(company_map or {})}
        self.records: dict[str, DeviceRecord] = {}

    async def receive(self) -> dict[str, DeviceRecord]:
        if BleakScanner is None:
            raise RuntimeError("Missing bleak. Run: pip install -r requirements.txt")

        discovered = await BleakScanner.discover(timeout=self.scan_seconds, return_adv=True)
        now = datetime.now(timezone.utc)

        for key, (device, adv) in discovered.items():
            address = device.address or key
            display_name = device.name or adv.local_name or "Desconocido"

            manufacturer_ids = sorted((adv.manufacturer_data or {}).keys())
            manufacturer_names = [self.company_map.get(mid, f"CID:{mid}") for mid in manufacturer_ids]
            service_uuids = sorted(set((adv.service_uuids or []) + list((adv.service_data or {}).keys())))
            service_labels = resolve_service_labels(service_uuids)

            if address in self.records:
                rec = self.records[address]
                rec.hits += 1
                rec.last_seen = now
            else:
                rec = DeviceRecord(
                    address=address,
                    display_name=display_name,
                    local_name=adv.local_name,
                    first_seen=now,
                    last_seen=now,
                )
                self.records[address] = rec

            rec.display_name = display_name
            rec.local_name = adv.local_name
            rec.manufacturer_ids = manufacturer_ids
            rec.manufacturer_names = manufacturer_names
            rec.service_uuids = service_uuids
            rec.service_labels = service_labels
            rec.service_data_uuids = sorted((adv.service_data or {}).keys())
            rec.tx_power = adv.tx_power
            rec.rssi_raw = adv.rssi
            rec.rssi_ema = self._ema(rec.rssi_ema if rec.hits > 1 else float(adv.rssi), adv.rssi)
            rec.distance_m = estimate_distance(rec.rssi_ema, self.rssi_ref, self.path_loss_exponent)
            rec.probable_type = infer_device_type(rec.display_name, rec.service_labels, rec.service_uuids)
            rec.address_privacy_hint = address_privacy_hint(rec.address)

        if self.active_probe:
            await self._run_active_probe()

        return self.records

    def _ema(self, current: float, new_value: float) -> float:
        return (self.ema_alpha * new_value) + ((1.0 - self.ema_alpha) * current)

    async def _run_active_probe(self) -> None:
        auditor = ActiveGattAuditor(
            timeout=self.probe_timeout,
            include_serial=self.include_serial,
            deep_read=self.deep_audit,
            read_descriptors=self.read_descriptors,
            max_read_bytes=self.max_read_bytes,
        )
        candidates = self._audit_candidates()
        for device in candidates:
            if device.active_probe:
                continue
            device.active_probe = await auditor.audit(device.address)

    def _audit_candidates(self) -> list[DeviceRecord]:
        records = sorted(self.records.values(), key=lambda d: d.rssi_ema, reverse=True)
        if not self.target_filters:
            return records[: self.probe_limit]

        matched = []
        for device in records:
            haystack = f"{device.address} {device.display_name} {device.local_name or ''}".lower()
            if any(target in haystack for target in self.target_filters):
                matched.append(device)
        return matched[: self.probe_limit]


def run_receive_sync(receiver: DeviceReceiver) -> dict[str, DeviceRecord]:
    return asyncio.run(receiver.receive())
