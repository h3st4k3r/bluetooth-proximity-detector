from __future__ import annotations

from typing import Any

from .enrichment import normalize_uuid, uuid_label

try:
    from bleak import BleakClient
except Exception:  # pragma: no cover
    BleakClient = None


DIS_CHARS = {
    "manufacturer_name": "00002A29-0000-1000-8000-00805F9B34FB",
    "model_number": "00002A24-0000-1000-8000-00805F9B34FB",
    "serial_number": "00002A25-0000-1000-8000-00805F9B34FB",
    "hardware_revision": "00002A27-0000-1000-8000-00805F9B34FB",
    "firmware_revision": "00002A26-0000-1000-8000-00805F9B34FB",
    "software_revision": "00002A28-0000-1000-8000-00805F9B34FB",
}


class ActiveGattAuditor:
    """Read-only GATT surface auditor for authorized Bluetooth assessments."""

    def __init__(
        self,
        timeout: float = 7.0,
        include_serial: bool = False,
        deep_read: bool = False,
        read_descriptors: bool = False,
        max_read_bytes: int = 96,
    ) -> None:
        self.timeout = timeout
        self.include_serial = include_serial
        self.deep_read = deep_read
        self.read_descriptors = read_descriptors
        self.max_read_bytes = max(1, max_read_bytes)

    async def audit(self, address: str) -> dict[str, Any]:
        if BleakClient is None:
            return {"error": "Missing bleak. Run: pip install -r requirements.txt"}

        result: dict[str, Any] = {
            "connectable": False,
            "device_information": {},
            "gatt_surface": [],
            "exposure_flags": [],
            "metrics": {},
        }

        try:
            async with BleakClient(address, timeout=self.timeout) as client:
                result["connectable"] = bool(client.is_connected)
                result["mtu_size"] = getattr(client, "mtu_size", None)
                result["device_information"] = await self._read_device_information(client)
                result["gatt_surface"] = await self._enumerate_services(client)
                result["metrics"] = self._calculate_metrics(result["gatt_surface"])
                result["exposure_flags"] = self._derive_flags(
                    result["gatt_surface"],
                    result["device_information"],
                    result["metrics"],
                )
        except Exception as exc:
            result["error"] = str(exc)

        return result

    async def _read_device_information(self, client: Any) -> dict[str, str]:
        info: dict[str, str] = {}
        for field, uuid in DIS_CHARS.items():
            if field == "serial_number" and not self.include_serial:
                continue
            try:
                raw = await client.read_gatt_char(uuid)
            except Exception:
                continue
            txt = raw.decode("utf-8", errors="ignore").strip()
            if txt:
                info[field] = txt
        return info

    async def _enumerate_services(self, client: Any) -> list[dict[str, Any]]:
        services_out: list[dict[str, Any]] = []

        for service in client.services:
            chars = []
            for char in service.characteristics:
                props = sorted(str(p) for p in getattr(char, "properties", []))
                descriptors = []
                for desc in getattr(char, "descriptors", []):
                    desc_out: dict[str, Any] = {
                        "uuid": str(getattr(desc, "uuid", "")),
                        "handle": getattr(desc, "handle", None),
                    }
                    if self.read_descriptors:
                        desc_out["read_result"] = await self._read_descriptor(client, desc)
                    descriptors.append(desc_out)

                char_out: dict[str, Any] = {
                    "uuid": str(char.uuid),
                    "label": uuid_label(str(char.uuid)),
                    "handle": getattr(char, "handle", None),
                    "description": str(getattr(char, "description", "")),
                    "properties": props,
                    "descriptors": descriptors,
                }
                if self.deep_read and "read" in props:
                    char_out["read_result"] = await self._read_characteristic(client, char)

                chars.append(
                    char_out
                )

            services_out.append(
                {
                    "uuid": str(service.uuid),
                    "label": uuid_label(str(service.uuid)),
                    "description": str(getattr(service, "description", "")),
                    "characteristics": chars,
                }
            )

        return services_out

    async def _read_characteristic(self, client: Any, char: Any) -> dict[str, Any]:
        try:
            raw = await client.read_gatt_char(char.uuid)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, **self._format_bytes(raw)}

    async def _read_descriptor(self, client: Any, desc: Any) -> dict[str, Any]:
        handle = getattr(desc, "handle", None)
        if handle is None:
            return {"ok": False, "error": "descriptor_without_handle"}
        try:
            raw = await client.read_gatt_descriptor(handle)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        return {"ok": True, **self._format_bytes(raw)}

    def _format_bytes(self, raw: bytes) -> dict[str, Any]:
        sample = raw[: self.max_read_bytes]
        out: dict[str, Any] = {
            "length": len(raw),
            "truncated": len(raw) > self.max_read_bytes,
            "hex": sample.hex(),
        }
        text = sample.decode("utf-8", errors="ignore").strip()
        if text and self._is_mostly_printable(text):
            out["utf8"] = text
        return out

    def _is_mostly_printable(self, text: str) -> bool:
        if not text:
            return False
        printable = sum(1 for ch in text if ch.isprintable())
        return printable / len(text) >= 0.85

    def _calculate_metrics(self, services: list[dict[str, Any]]) -> dict[str, int]:
        metrics = {
            "services": len(services),
            "characteristics": 0,
            "readable_characteristics": 0,
            "readable_without_error": 0,
            "writable_characteristics": 0,
            "write_without_response_characteristics": 0,
            "notify_or_indicate_characteristics": 0,
            "descriptors": 0,
            "descriptors_read_without_error": 0,
        }

        for service in services:
            for char in service.get("characteristics", []):
                metrics["characteristics"] += 1
                props = set(char.get("properties", []))
                metrics["descriptors"] += len(char.get("descriptors", []))
                if "read" in props:
                    metrics["readable_characteristics"] += 1
                if char.get("read_result", {}).get("ok"):
                    metrics["readable_without_error"] += 1
                if "write" in props:
                    metrics["writable_characteristics"] += 1
                if "write-without-response" in props:
                    metrics["write_without_response_characteristics"] += 1
                if "notify" in props or "indicate" in props:
                    metrics["notify_or_indicate_characteristics"] += 1
                for desc in char.get("descriptors", []):
                    if desc.get("read_result", {}).get("ok"):
                        metrics["descriptors_read_without_error"] += 1

        return metrics

    def _derive_flags(
        self,
        services: list[dict[str, Any]],
        device_info: dict[str, str],
        metrics: dict[str, int],
    ) -> list[dict[str, Any]]:
        flags: list[dict[str, Any]] = []
        write_chars = []
        write_no_rsp_chars = []
        notify_chars = []
        readable_chars = []
        fitness_control_points = []

        for service in services:
            service_uuid = normalize_uuid(service.get("uuid", ""))
            for char in service.get("characteristics", []):
                char_uuid = normalize_uuid(char.get("uuid", ""))
                props = set(char.get("properties", []))
                if "write-without-response" in props:
                    write_no_rsp_chars.append({**char, "service_uuid": service.get("uuid"), "mode": "write-without-response"})
                if "write" in props:
                    write_chars.append({**char, "service_uuid": service.get("uuid"), "mode": "write"})
                if "notify" in props or "indicate" in props:
                    notify_chars.append({**char, "service_uuid": service.get("uuid")})
                if char.get("read_result", {}).get("ok"):
                    readable_chars.append({**char, "service_uuid": service.get("uuid")})
                if (
                    service_uuid == "00001826-0000-1000-8000-00805f9b34fb"
                    and char_uuid == "00002ad9-0000-1000-8000-00805f9b34fb"
                    and ("write" in props or "write-without-response" in props)
                ):
                    fitness_control_points.append({**char, "service_uuid": service.get("uuid")})

        writable_total = len(write_chars) + len(write_no_rsp_chars)
        writable_evidence = (write_no_rsp_chars + write_chars)[:10]

        if writable_total:
            flags.append(
                {
                    "id": "gatt-write-surface",
                    "severity": "medium",
                    "summary": "Writable GATT characteristics exposed",
                    "evidence_count": writable_total,
                    "evidence": writable_evidence,
                }
            )

        if write_no_rsp_chars:
            flags.append(
                {
                    "id": "gatt-write-without-response",
                    "severity": "medium",
                    "summary": "Characteristics with write-without-response",
                    "evidence_count": len(write_no_rsp_chars),
                    "evidence": write_no_rsp_chars[:10],
                }
            )

        if fitness_control_points:
            flags.append(
                {
                    "id": "fitness-machine-control-point-write",
                    "severity": "high",
                    "summary": "Writable Fitness Machine Control Point",
                    "evidence_count": len(fitness_control_points),
                    "evidence": fitness_control_points[:10],
                }
            )

        if notify_chars:
            flags.append(
                {
                    "id": "gatt-notify-surface",
                    "severity": "info",
                    "summary": "Characteristics with notify/indicate available",
                    "evidence_count": len(notify_chars),
                    "evidence": notify_chars[:10],
                }
            )

        if readable_chars:
            flags.append(
                {
                    "id": "gatt-readable-surface",
                    "severity": "info",
                    "summary": "GATT characteristics readable during the audit",
                    "evidence_count": len(readable_chars),
                    "evidence": readable_chars[:10],
                }
            )

        if device_info:
            flags.append(
                {
                    "id": "device-info-readable",
                    "severity": "info",
                    "summary": "Device Information Service readable without additional steps",
                    "fields": sorted(device_info.keys()),
                }
            )

        if metrics.get("services", 0) >= 8 or metrics.get("characteristics", 0) >= 30:
            flags.append(
                {
                    "id": "large-gatt-surface",
                    "severity": "low",
                    "summary": "Large GATT surface",
                    "metrics": metrics,
                }
            )

        return flags
