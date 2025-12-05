# Quick Start Guide

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Basic Usage

### 1. Find your Anker devices
```bash
python3 anker_prime_cli.py scan
```

### 2. Get device information
```bash
# Auto-connect to first device
python3 anker_prime_cli.py info

# Or specify device
python3 anker_prime_cli.py info --address 7C:E9:13:65:4D:12
```

### 3. Check status
```bash
python3 anker_prime_cli.py status
```

### 4. Monitor in real-time
```bash
# Monitor with 5 second intervals
python3 anker_prime_cli.py monitor --interval 5
```

## Common Examples

### Monitor specific device
```bash
python3 anker_prime_cli.py monitor --address 7C:E9:13:65:4D:12 --interval 2
```

### Get status with extended monitoring
```bash
python3 anker_prime_cli.py status --monitor-time 30
```

## Tips

- First time: Run `scan` to find your device address
- Use `--address` to connect to a specific device
- Press `Ctrl+C` to stop monitoring
- Check README.md for detailed documentation

## Troubleshooting

**Permission denied?**
```bash
sudo usermod -a -G bluetooth $USER
# Log out and back in
```

**No devices found?**
```bash
# Check Bluetooth is on
bluetoothctl power on

# Scan with bluetoothctl
bluetoothctl scan on
```

**Import errors?**
```bash
# Make sure you're in the right directory
cd anker-vibecoded
pip install -r requirements.txt
```
