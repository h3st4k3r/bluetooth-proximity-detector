from __future__ import annotations

from .models import DeviceRecord, RiskFinding

SWEYNTOOTH_VENDORS = {
    "texas instruments",
    "nxp",
    "cypress semiconductor",
    "microchip",
    "stmicroelectronics",
    "telink semiconductor",
    "espressif",
}

BRAKTOOTH_VENDORS = {
    "intel",
    "qualcomm",
    "infineon",
    "cypress semiconductor",
    "silicon labs",
    "texas instruments",
}


class RiskEngine:
    def evaluate(self, device: DeviceRecord) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        vendor_blob = " ".join(device.manufacturer_names).lower()
        name_blob = (device.display_name or "").lower()

        if any(v in vendor_blob for v in SWEYNTOOTH_VENDORS):
            findings.append(
                RiskFinding(
                    title="Possible SweynTooth exposure",
                    severity="medium",
                    confidence=0.45,
                    rationale="The observed vendor has historically appeared in BLE stack vulnerability families.",
                    recommendation="Validate the exact model/firmware against OEM advisories and apply available patches.",
                )
            )

        if any(v in vendor_blob for v in BRAKTOOTH_VENDORS):
            findings.append(
                RiskFinding(
                    title="Possible BrakTooth exposure",
                    severity="medium",
                    confidence=0.40,
                    rationale="The observed vendor has appeared in research around Bluetooth Classic issues.",
                    recommendation="Check firmware status and harden BR/EDR profiles in the lab scope.",
                )
            )

        if any(k in name_blob for k in ["headset", "speaker", "keyboard", "mouse", "car", "buds"]):
            findings.append(
                RiskFinding(
                    title="Review dual-mode hardening",
                    severity="low",
                    confidence=0.35,
                    rationale="The observed profile may be dual-mode (BLE + BR/EDR).",
                    recommendation="Limit pairing windows, update firmware, and disable discoverable mode when not needed.",
                )
            )

        if device.address_privacy_hint == "random_or_private":
            findings.append(
                RiskFinding(
                    title="Private BLE address",
                    severity="info",
                    confidence=0.9,
                    rationale="The observed address appears locally administered and compatible with BLE privacy behavior.",
                    recommendation="Correlate by fingerprint rather than relying on a stable MAC address.",
                )
            )

        device_info = device.active_probe.get("device_information", {}) if device.active_probe else {}
        exposure_flags = device.active_probe.get("exposure_flags", []) if device.active_probe else []

        if device_info and "firmware_revision" in device_info:
            findings.append(
                RiskFinding(
                    title="Firmware inventory available",
                    severity="info",
                    confidence=0.95,
                    rationale="The active audit obtained a firmware version that can be correlated with CVEs.",
                    recommendation="Cross-check the version against CVE data and vendor bulletins.",
                )
            )

        for flag in exposure_flags:
            if flag.get("id") == "gatt-write-surface":
                findings.append(
                    RiskFinding(
                        title="Writable GATT surface exposed",
                        severity="medium",
                        confidence=0.65,
                        rationale=(
                            "The active audit found GATT characteristics with write/write-without-response "
                            "properties. This does not confirm exploitability, but it is a surface that should "
                            "be reviewed against the exact model and firmware."
                        ),
                        recommendation=(
                            "Validate whether those characteristics require authentication/authorization, review "
                            "pairing controls, and document the expected vendor behavior."
                        ),
                    )
                )

            if flag.get("id") == "gatt-write-without-response":
                findings.append(
                    RiskFinding(
                        title="Write Without Response available",
                        severity="medium",
                        confidence=0.70,
                        rationale=(
                            "Characteristics with write-without-response were observed; this is a relevant "
                            "surface for reviewing input validation, pairing controls, and authorization."
                        ),
                        recommendation=(
                            "Confirm that writes require appropriate authorization and only test agreed cases "
                            "inside the lab scope."
                        ),
                    )
                )

            if flag.get("id") == "fitness-machine-control-point-write":
                findings.append(
                    RiskFinding(
                        title="Writable Fitness Machine Control Point",
                        severity="high",
                        confidence=0.80,
                        rationale=(
                            "The device exposes a writable Fitness Machine Control Point. On fitness equipment, "
                            "this control point can be related to session control, state, or operational parameters, "
                            "so it deserves priority review in the lab."
                        ),
                        recommendation=(
                            "Validate whether the control point requires pairing, bonding, or application-level "
                            "authorization; document supported commands only with isolated equipment in scope."
                        ),
                    )
                )

            if flag.get("id") == "gatt-readable-surface":
                findings.append(
                    RiskFinding(
                        title="Readable GATT characteristics",
                        severity="low",
                        confidence=0.75,
                        rationale="The deep audit read GATT values without errors.",
                        recommendation=(
                            "Review whether exposed values contain configuration, identifiers, or telemetry that "
                            "should not be available to unauthenticated users."
                        ),
                    )
                )

            if flag.get("id") == "large-gatt-surface":
                findings.append(
                    RiskFinding(
                        title="Large GATT surface",
                        severity="low",
                        confidence=0.60,
                        rationale="The device exposes a high number of services/characteristics.",
                        recommendation="Prioritize manual review of writable and readable characteristics.",
                    )
                )

            if flag.get("id") == "device-info-readable":
                findings.append(
                    RiskFinding(
                        title="Device information exposed",
                        severity="info",
                        confidence=0.85,
                        rationale="The device allows Device Information Service metadata to be read.",
                        recommendation="Use these fields to correlate firmware with CVEs and OEM bulletins.",
                    )
                )

        return findings
