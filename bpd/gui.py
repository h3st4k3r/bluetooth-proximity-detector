from __future__ import annotations

import asyncio
import json
import math
import random
import textwrap
from typing import Any

from .models import DeviceRecord
from .service import AuditService


class BPDGui:
    def __init__(self, service: AuditService, refresh_seconds: float = 12.0, title: str = "Bluetooth Proximity Detector") -> None:
        try:
            import tkinter as tk
            from tkinter import ttk
        except Exception as exc:
            raise RuntimeError("Tkinter no disponible. Usa --no-gui o instala Python con soporte Tk.") from exc

        self.tk = tk
        self.ttk = ttk
        self.service = service
        self.refresh_seconds = refresh_seconds
        self.records: list[DeviceRecord] = []

        self.root = self.tk.Tk()
        self.root.title(title)
        self.root.geometry("1220x760")

        self.main = self.ttk.Frame(self.root, padding=8)
        self.main.pack(fill=self.tk.BOTH, expand=True)

        self.topbar = self.ttk.Frame(self.main)
        self.topbar.pack(fill=self.tk.X, pady=(0, 8))

        self.btn_scan = self.ttk.Button(self.topbar, text="Escanear ahora", command=self.scan_now)
        self.btn_scan.pack(side=self.tk.LEFT)

        self.auto_var = self.tk.BooleanVar(value=True)
        self.chk_auto = self.ttk.Checkbutton(self.topbar, text="Auto-refresh", variable=self.auto_var)
        self.chk_auto.pack(side=self.tk.LEFT, padx=8)

        self.status = self.ttk.Label(self.topbar, text="Listo")
        self.status.pack(side=self.tk.RIGHT)

        self.split = self.ttk.Panedwindow(self.main, orient=self.tk.HORIZONTAL)
        self.split.pack(fill=self.tk.BOTH, expand=True)

        self.left = self.ttk.Frame(self.split)
        self.right = self.ttk.Frame(self.split)
        self.split.add(self.left, weight=3)
        self.split.add(self.right, weight=2)

        cols = ("name", "addr", "rssi", "dist", "vendor", "dtype", "risk")
        self.tree = self.ttk.Treeview(self.left, columns=cols, show="headings", height=18)
        for key, title in [
            ("name", "Name"),
            ("addr", "Address"),
            ("rssi", "RSSI"),
            ("dist", "Distance (m)"),
            ("vendor", "Vendor"),
            ("dtype", "Probable type"),
            ("risk", "Risk"),
        ]:
            self.tree.heading(key, text=title)

        self.tree.column("name", width=180, anchor=self.tk.W)
        self.tree.column("addr", width=180, anchor=self.tk.W)
        self.tree.column("rssi", width=70, anchor=self.tk.E)
        self.tree.column("dist", width=95, anchor=self.tk.E)
        self.tree.column("vendor", width=180, anchor=self.tk.W)
        self.tree.column("dtype", width=120, anchor=self.tk.W)
        self.tree.column("risk", width=80, anchor=self.tk.CENTER)
        self.tree.pack(fill=self.tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.details = self.tk.Text(self.right, wrap=self.tk.WORD, height=30)
        self.details.pack(fill=self.tk.BOTH, expand=True)
        self.details.configure(state=self.tk.DISABLED)

        self.canvas = self.tk.Canvas(self.right, height=220, bg="#0d1117", highlightthickness=0)
        self.canvas.pack(fill=self.tk.X, pady=(8, 0))

    def run(self) -> None:
        self.scan_now()
        self._tick()
        self.root.mainloop()

    def _tick(self) -> None:
        if self.auto_var.get():
            self.scan_now()
        self.root.after(int(self.refresh_seconds * 1000), self._tick)

    def scan_now(self) -> None:
        self.status.configure(text="Scanning...")
        self.root.update_idletasks()
        try:
            result = asyncio.run(self.service.run_once())
            receiver = self.service.receiver
            self.records = sorted(getattr(receiver, "records", {}).values(), key=lambda x: (x.risk_score, x.rssi_ema), reverse=True)
            self._refresh_table()
            self._draw_radar()
            self.status.configure(text=f"Scan complete: {result.total} devices, HIGH={result.high_risk}")
        except Exception as exc:
            self.status.configure(text=f"Error: {exc}")

    def _refresh_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for rec in self.records:
            vendor = rec.manufacturer_names[0] if rec.manufacturer_names else "N/D"
            self.tree.insert(
                "",
                self.tk.END,
                iid=rec.address,
                values=(rec.display_name, rec.address, f"{rec.rssi_ema:.1f}", f"{rec.distance_m:.2f}", vendor, rec.probable_type, rec.risk_label),
            )

    def _on_select(self, _event: Any) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        target = selected[0]
        rec = next((d for d in self.records if d.address == target), None)
        if rec is None:
            return

        lines = [
            f"Name: {rec.display_name}",
            f"Address: {rec.address}",
            f"Probable type: {rec.probable_type}",
            f"Address privacy: {rec.address_privacy_hint}",
            f"Vendor(s): {', '.join(rec.manufacturer_names) if rec.manufacturer_names else 'N/A'}",
            f"RSSI EMA: {rec.rssi_ema:.2f} dBm",
            f"Estimated distance: {rec.distance_m:.2f} m",
            f"Risk: {rec.risk_label} ({rec.risk_score}/100)",
            "",
            "Active Audit:",
        ]
        if rec.active_probe:
            device_info = rec.active_probe.get("device_information", {})
            flags = rec.active_probe.get("exposure_flags", [])
            surface = rec.active_probe.get("gatt_surface", [])
            lines.append(f"- Connectable: {rec.active_probe.get('connectable', False)}")
            lines.append(f"- Servicios GATT: {len(surface)}")
            if device_info:
                lines.append("- Device Information:")
                for k, v in device_info.items():
                    lines.append(f"  {k}: {v}")
            if flags:
                lines.append("- Exposure flags:")
                for flag in flags:
                    lines.append(f"  [{flag.get('severity', 'info').upper()}] {flag.get('summary', flag.get('id'))}")
            if rec.active_probe.get("error"):
                lines.append(f"- Error: {rec.active_probe['error']}")
            lines.append("")
            lines.append(json.dumps(rec.active_probe, ensure_ascii=False, indent=2)[:4000])
        else:
            lines.append("- No active audit data.")

        lines.append("")
        lines.append("Findings:")
        if rec.findings:
            for finding in rec.findings:
                lines.append(
                    textwrap.dedent(
                        f"""
                        - [{finding.severity.upper()}] {finding.title} (conf {finding.confidence:.2f})
                          Rationale: {finding.rationale}
                          Recommendation: {finding.recommendation}
                        """
                    ).strip()
                )
        else:
            lines.append("- No findings from the current rules.")

        self.details.configure(state=self.tk.NORMAL)
        self.details.delete("1.0", self.tk.END)
        self.details.insert("1.0", "\n".join(lines))
        self.details.configure(state=self.tk.DISABLED)

    def _draw_radar(self) -> None:
        self.canvas.delete("all")
        w = max(self.canvas.winfo_width(), 300)
        h = max(self.canvas.winfo_height(), 220)
        cx, cy = w // 2, h // 2

        for radius in [30, 60, 90]:
            self.canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, outline="#2a2f3a")

        self.canvas.create_oval(cx - 4, cy - 4, cx + 4, cy + 4, fill="#ff4d4d", outline="")
        self.canvas.create_text(cx, cy - 12, text="YOU", fill="#ff4d4d")

        for rec in self.records:
            random.seed(sum(ord(ch) for ch in rec.address))
            angle = random.uniform(0, 2 * math.pi)
            dist = min(rec.distance_m, 12.0)
            radius = 12 + (dist / 12.0) * 95
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)

            color = "#30c48d"
            if rec.risk_label == "MEDIUM":
                color = "#f7b731"
            elif rec.risk_label == "HIGH":
                color = "#ff5e57"

            self.canvas.create_line(cx, cy, x, y, fill="#394150")
            self.canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill=color, outline="")
