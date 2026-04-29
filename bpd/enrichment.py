from __future__ import annotations

import re

COMPANY_ID_MAP: dict[int, str] = {
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x004C: "Apple",
    0x0059: "Nordic Semiconductor",
    0x0075: "Samsung Electronics",
    0x0087: "Garmin",
    0x00E0: "Google",
    0x0131: "Cypress Semiconductor",
    0x0211: "Bose",
    0x038F: "Xiaomi",
}

SERVICE_UUID_LABELS: dict[str, str] = {
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "0000181a-0000-1000-8000-00805f9b34fb": "Environmental Sensing",
    "00001822-0000-1000-8000-00805f9b34fb": "Pulse Oximeter",
    "00001826-0000-1000-8000-00805f9b34fb": "Fitness Machine",
    "00001843-0000-1000-8000-00805f9b34fb": "Audio Input Control",
    "00001844-0000-1000-8000-00805f9b34fb": "Volume Control",
}

CHARACTERISTIC_UUID_LABELS: dict[str, str] = {
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number String",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number String",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision String",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision String",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision String",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name String",
    "00002acc-0000-1000-8000-00805f9b34fb": "Fitness Machine Feature",
    "00002acd-0000-1000-8000-00805f9b34fb": "Treadmill Data",
    "00002ace-0000-1000-8000-00805f9b34fb": "Cross Trainer Data",
    "00002acf-0000-1000-8000-00805f9b34fb": "Step Climber Data",
    "00002ad0-0000-1000-8000-00805f9b34fb": "Stair Climber Data",
    "00002ad1-0000-1000-8000-00805f9b34fb": "Rower Data",
    "00002ad2-0000-1000-8000-00805f9b34fb": "Indoor Bike Data",
    "00002ad3-0000-1000-8000-00805f9b34fb": "Training Status",
    "00002ad4-0000-1000-8000-00805f9b34fb": "Supported Speed Range",
    "00002ad5-0000-1000-8000-00805f9b34fb": "Supported Inclination Range",
    "00002ad6-0000-1000-8000-00805f9b34fb": "Supported Resistance Level Range",
    "00002ad7-0000-1000-8000-00805f9b34fb": "Supported Heart Rate Range",
    "00002ad8-0000-1000-8000-00805f9b34fb": "Supported Power Range",
    "00002ad9-0000-1000-8000-00805f9b34fb": "Fitness Machine Control Point",
    "00002ada-0000-1000-8000-00805f9b34fb": "Fitness Machine Status",
}

TYPE_HINTS = {
    "smartphone": ["iphone", "android", "pixel", "galaxy", "phone"],
    "laptop": ["macbook", "laptop", "thinkpad", "notebook"],
    "audio": ["airpods", "buds", "headset", "speaker", "audio", "bose", "sony"],
    "wearable": ["watch", "band", "fit", "garmin"],
    "iot/sensor": ["sensor", "beacon", "tag", "tracker", "meter", "thermo"],
    "mouse-keyboard": ["mouse", "keyboard", "trackpad", "hid"],
    "automotive": ["car", "vehicle", "bmw", "audi", "tesla"],
    "medical": ["glucose", "heart", "oximeter", "med", "hospital"],
}


def normalize_uuid(value: str) -> str:
    value = value.lower()
    short_hex = value.replace("-", "")
    if len(short_hex) == 4:
        return f"0000{short_hex}-0000-1000-8000-00805f9b34fb"
    return value


def resolve_service_labels(uuids: list[str]) -> list[str]:
    labels: list[str] = []
    for uuid in uuids:
        label = SERVICE_UUID_LABELS.get(normalize_uuid(uuid))
        if label:
            labels.append(label)
    return sorted(set(labels))


def uuid_label(uuid: str) -> str:
    normalized = normalize_uuid(uuid)
    return SERVICE_UUID_LABELS.get(normalized) or CHARACTERISTIC_UUID_LABELS.get(normalized) or ""


def infer_device_type(name: str, service_labels: list[str], service_uuids: list[str]) -> str:
    text = (name or "").lower()
    for kind, keywords in TYPE_HINTS.items():
        if any(k in text for k in keywords):
            return kind

    labels_text = " ".join(service_labels).lower()
    if "pulse oximeter" in labels_text:
        return "medical"
    if "human interface device" in labels_text:
        return "mouse-keyboard"
    if "audio" in labels_text:
        return "audio"
    if "fitness machine" in labels_text:
        return "fitness-machine"
    if service_uuids:
        return "ble-generic"
    return "desconocido"


def estimate_distance(rssi: float, rssi_ref: int, path_loss_exponent: float) -> float:
    ratio_db = rssi_ref - rssi
    ratio_linear = 10 ** (ratio_db / (10 * path_loss_exponent))
    return max(0.05, float(ratio_linear))


def address_privacy_hint(address: str) -> str:
    mac_re = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    if not mac_re.match(address):
        return "non-mac-id"
    first_octet = int(address.split(":")[0], 16)
    return "random_or_private" if (first_octet & 0b00000010) else "public"
