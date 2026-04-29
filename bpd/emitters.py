from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from .models import DeviceRecord

try:
    import requests
except Exception:  # pragma: no cover
    requests = None


class DeviceEmitter(ABC):
    @abstractmethod
    def emit(self, devices: list[DeviceRecord]) -> None:
        raise NotImplementedError


class ConsoleEmitter(DeviceEmitter):
    def __init__(self, top: int = 25, details: bool = False) -> None:
        self.top = top
        self.details = details

    def emit(self, devices: list[DeviceRecord]) -> None:
        rows = sorted(devices, key=lambda r: (r.risk_score, r.rssi_ema), reverse=True)[: self.top]
        header = (
            f"{'Name':24} {'Address':20} {'RSSI':>6} {'Dist(m)':>8} "
            f"{'Type':14} {'Risk':>7} {'W':>3} {'R':>3} {'Svc':>4}"
        )
        print(header)
        print("-" * len(header))
        for rec in rows:
            metrics = rec.active_probe.get("metrics", {}) if rec.active_probe else {}
            print(
                f"{rec.display_name[:24]:24} {rec.address[:20]:20} {rec.rssi_ema:6.1f} {rec.distance_m:8.2f} "
                f"{rec.probable_type[:14]:14} {rec.risk_label:>7} "
                f"{metrics.get('writable_characteristics', 0) + metrics.get('write_without_response_characteristics', 0):3d} "
                f"{metrics.get('readable_without_error', 0):3d} "
                f"{metrics.get('services', 0):4d}"
            )

        if self.details:
            self._emit_details(rows)

    def _emit_details(self, rows: list[DeviceRecord]) -> None:
        for rec in rows:
            if not rec.findings and not rec.active_probe:
                continue

            print()
            print(f"== {rec.display_name} [{rec.address}] ==")
            print(f"RSSI={rec.rssi_ema:.1f} dBm Dist={rec.distance_m:.2f}m Type={rec.probable_type} Risk={rec.risk_label}")

            if rec.findings:
                print("Findings:")
                for finding in rec.findings:
                    print(f"- [{finding.severity.upper()}] {finding.title} (conf {finding.confidence:.2f})")
                    print(f"  Rationale: {finding.rationale}")
                    print(f"  Recommendation: {finding.recommendation}")

            if not rec.active_probe:
                continue

            probe = rec.active_probe
            if probe.get("error"):
                print(f"Active audit error: {probe['error']}")

            metrics = probe.get("metrics", {})
            if metrics:
                print(
                    "GATT metrics: "
                    f"svc={metrics.get('services', 0)} "
                    f"chars={metrics.get('characteristics', 0)} "
                    f"readable={metrics.get('readable_characteristics', 0)} "
                    f"read_ok={metrics.get('readable_without_error', 0)} "
                    f"write={metrics.get('writable_characteristics', 0)} "
                    f"write_no_rsp={metrics.get('write_without_response_characteristics', 0)} "
                    f"notify={metrics.get('notify_or_indicate_characteristics', 0)}"
                )

            device_info = probe.get("device_information", {})
            if device_info:
                print("Device Information:")
                for key, value in device_info.items():
                    print(f"- {key}: {value}")

            flags = probe.get("exposure_flags", [])
            if flags:
                print("Exposure flags:")
                for flag in flags:
                    print(f"- [{flag.get('severity', 'info').upper()}] {flag.get('summary', flag.get('id'))}")
                    for evidence in flag.get("evidence", [])[:3]:
                        service_uuid = evidence.get("service_uuid", "?")
                        char_uuid = evidence.get("uuid", "?")
                        label = evidence.get("label") or evidence.get("description") or "unlabeled"
                        props = ",".join(evidence.get("properties", []))
                        print(f"  {service_uuid} -> {char_uuid} ({label}) props={props}")
                        read_result = evidence.get("read_result", {})
                        if read_result.get("ok"):
                            sample = read_result.get("utf8") or read_result.get("hex", "")
                            print(f"    read len={read_result.get('length', 0)} sample={sample}")


class JsonFileEmitter(DeviceEmitter):
    def __init__(self, out_file: Path) -> None:
        self.out_file = out_file

    def emit(self, devices: list[DeviceRecord]) -> None:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "devices": [d.to_dict() for d in devices],
        }
        self.out_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


class WebhookEmitter(DeviceEmitter):
    def __init__(self, url: str, timeout: float = 8.0) -> None:
        self.url = url
        self.timeout = timeout

    def emit(self, devices: list[DeviceRecord]) -> None:
        if requests is None:
            return
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "devices": [d.to_dict() for d in devices],
        }
        try:
            requests.post(self.url, json=payload, timeout=self.timeout)
        except Exception:
            # Do not interrupt the audit pipeline because of an output failure.
            return
