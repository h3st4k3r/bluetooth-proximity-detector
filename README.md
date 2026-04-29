# Bluetooth Proximity Detector (BPD)

Object-oriented Bluetooth discovery and read-only audit toolkit for authorized lab assessments.

<img width="1641" height="775" alt="image" src="https://github.com/user-attachments/assets/66e8cc8e-52b5-403b-956e-795791bf5391" />


## Architecture

- `bpd/receiver.py`: receiver layer (`DeviceReceiver`) and BLE backend (`BleDeviceReceiver`).
- `bpd/active_audit.py`: read-only active auditor (`ActiveGattAuditor`) for GATT surface enumeration.
- `bpd/risk.py`: risk evaluation engine (`RiskEngine`).
- `bpd/emitters.py`: output layer (`DeviceEmitter`) with console, JSON, and webhook emitters.
- `bpd/service.py`: orchestrator (`AuditService`) connecting receive, risk, and emit stages.
- `bpd/gui.py`: desktop GUI.
- `bpd/cli.py`: CLI entry point and component wiring.

## Features

- BLE discovery with RSSI smoothing (EMA).
- Vendor classification through Bluetooth Company IDs.
- Probable device-type inference from names and GATT services.
- Read-only active audit mode (`--active-audit`) for Device Information Service and GATT enumeration.
- Deep read-only audit mode (`--deep-audit`) for readable GATT characteristics.
- Optional descriptor reads (`--read-descriptors`) when supported by the backend.
- Fitness Machine profile labeling and explicit detection of writable Fitness Machine Control Point exposure.
- Reusable outputs: console table, detailed console evidence, JSON export, and webhook delivery.

## Requirements

- Python 3.10+
- Compatible Bluetooth adapter
- Operating-system Bluetooth permissions
- Python dependencies:

```bash
pip install -r requirements.txt
```

Using a virtual environment is recommended on macOS/Homebrew Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### GUI

```bash
python bpd.py
```

### CLI

```bash
python bpd.py --no-gui
```

### Local Diagnostics

```bash
python bpd.py --diagnostics
```

### CLI + JSON Export

```bash
python bpd.py --no-gui --export-json results.json
```

### CLI With Console Evidence

```bash
python bpd.py --no-gui --active-audit --deep-audit --details
```

### CLI + Webhook

```bash
python bpd.py --no-gui --webhook-url https://your-siem.local/ingest
```

### Read-Only Active Audit

```bash
python bpd.py --no-gui --active-audit --probe-limit 5
```

### Deep Read-Only Audit

```bash
python bpd.py --no-gui --active-audit --deep-audit --read-descriptors --probe-limit 5 --max-read-bytes 128 --export-json results.json
```

`--deep-audit` and `--read-descriptors` automatically enable active auditing.

### Target a Specific Device

Filter active auditing by name or address:

```bash
python bpd.py --no-gui --active-audit --deep-audit --details --target Mobvoi
```

`--target` is repeatable.

### Include Serial Number

Only use this when serial-number collection is explicitly in scope:

```bash
python bpd.py --no-gui --active-audit --include-serial --export-json results.json
```

### Calibration and Tuning

```bash
python bpd.py --no-gui --scan-seconds 8 --rssi-ref -58 --path-loss-exponent 2.4 --ema-alpha 0.4
```

## Extended Vendor Map

CSV format: `id,name` or `0xNNNN,name`.

```csv
0x004C,Apple
0x00E0,Google
```

Usage:

```bash
python bpd.py --no-gui --company-map company_ids.csv
```

## Safety and Scope

- This project does not implement exploitation, offensive fuzzing, bypasses, MITM, or active GATT writes.
- `--active-audit` connects and enumerates services in read-only mode.
- `--deep-audit` only reads characteristics and descriptors that the device itself exposes as readable.
- The risk score is directional and does not replace firmware-specific validation against CVEs or vendor advisories.
- Use only with explicit written authorization and inside the agreed assessment scope.
