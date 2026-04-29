from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import platform
import sys
from pathlib import Path

from .emitters import ConsoleEmitter, JsonFileEmitter, WebhookEmitter
from .enrichment import COMPANY_ID_MAP
from .gui import BPDGui
from .receiver import BleDeviceReceiver
from .service import AuditService


def load_company_map(csv_path: Path) -> dict[int, str]:
    mapping: dict[int, str] = {}
    if not csv_path.exists():
        return mapping
    for line in csv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        try:
            key = int(parts[0], 16) if parts[0].lower().startswith("0x") else int(parts[0])
        except ValueError:
            continue
        mapping[key] = parts[1]
    return mapping


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Bluetooth Proximity Detector - object-oriented defensive audit toolkit")
    p.add_argument("--scan-seconds", type=float, default=6.0)
    p.add_argument("--rssi-ref", type=int, default=-60)
    p.add_argument("--path-loss-exponent", type=float, default=2.0)
    p.add_argument("--ema-alpha", type=float, default=0.35)
    p.add_argument("--no-gui", action="store_true")
    p.add_argument("--refresh-seconds", type=float, default=12.0)
    p.add_argument("--top", type=int, default=25)
    p.add_argument("--details", action="store_true", help="Print findings and GATT evidence to the console")
    p.add_argument("--target", action="append", default=[], help="Filter active audit by name or address; repeatable")
    p.add_argument("--export-json", type=Path)
    p.add_argument("--webhook-url", type=str)
    p.add_argument("--company-map", type=Path)
    p.add_argument("--diagnostics", action="store_true", help="Show Python, bleak, and local backend status")
    p.add_argument("--active-probe", action="store_true", help="Alias for --active-audit")
    p.add_argument("--active-audit", action="store_true", help="Read-only active audit: enumerate GATT surface and DIS")
    p.add_argument("--deep-audit", action="store_true", help="Read GATT characteristics with the read property during the audit")
    p.add_argument("--read-descriptors", action="store_true", help="Read GATT descriptors when the backend allows it")
    p.add_argument("--probe-limit", type=int, default=3)
    p.add_argument("--probe-timeout", type=float, default=7.0)
    p.add_argument("--max-read-bytes", type=int, default=96)
    p.add_argument("--include-serial", action="store_true", help="Include serial number if the device exposes it")
    return p


def build_service(args: argparse.Namespace) -> AuditService:
    ext_map = load_company_map(args.company_map) if args.company_map else {}
    company_map = {**COMPANY_ID_MAP, **ext_map}
    active_requested = args.active_probe or args.active_audit or args.deep_audit or args.read_descriptors
    receiver = BleDeviceReceiver(
        scan_seconds=args.scan_seconds,
        rssi_ref=args.rssi_ref,
        path_loss_exponent=args.path_loss_exponent,
        ema_alpha=args.ema_alpha,
        company_map=company_map,
        active_probe=active_requested,
        probe_limit=max(1, args.probe_limit),
        probe_timeout=args.probe_timeout,
        include_serial=args.include_serial,
        deep_audit=args.deep_audit,
        read_descriptors=args.read_descriptors,
        max_read_bytes=args.max_read_bytes,
        target_filters=args.target,
    )

    emitters = [ConsoleEmitter(top=args.top, details=args.details)]
    if args.export_json:
        emitters.append(JsonFileEmitter(args.export_json))
    if args.webhook_url:
        emitters.append(WebhookEmitter(args.webhook_url))

    return AuditService(receiver=receiver, emitters=emitters)


def print_diagnostics() -> None:
    print("BPD diagnostics")
    print(f"- Python: {platform.python_version()}")
    print(f"- Executable: {sys.executable}")
    print(f"- Platform: {platform.platform()}")
    try:
        version = importlib.metadata.version("bleak")
        print(f"- bleak: {version}")
    except importlib.metadata.PackageNotFoundError:
        print("- bleak: not installed")

    try:
        import bleak  # noqa: F401

        print("- bleak import: ok")
    except Exception as exc:
        print(f"- bleak import: error: {exc}")


def main() -> int:
    args = build_parser().parse_args()
    if args.diagnostics:
        print_diagnostics()
        return 0

    service = build_service(args)

    if args.no_gui:
        try:
            result = asyncio.run(service.run_once())
            if args.export_json:
                print(f"\nJSON exported to: {args.export_json}")
            print(f"\nSummary: total={result.total}, high_risk={result.high_risk}")
            return 0
        except Exception as exc:
            print(f"CLI error: {exc}")
            return 1

    try:
        app = BPDGui(service=service, refresh_seconds=args.refresh_seconds)
        app.run()
        return 0
    except Exception as exc:
        print(f"GUI error: {exc}")
        return 1
