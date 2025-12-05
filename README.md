# Anker Prime BLE Tool

A Python tool for connecting to and monitoring Anker Prime power banks via Bluetooth LE.

lol this is vibecoded so it barely works. it's all just from https://github.com/atc1441/Anker_Prime_BLE_hacking but it doesn't seem to work with my Anker devices. was fun to watch Claude try though.

## Features

- 🔍 Scan for Anker Prime devices
- 📊 Read device information (firmware, serial, MAC)
- 🔐 Encrypted communication using AES-CBC
- 📈 Request device status and telemetry
- 🔄 Real-time monitoring mode

## Requirements

- Python 3.7+
- Linux with BlueZ (for Bluetooth support)
- Anker Prime power bank with BLE support

## Installation

1. Clone or download this repository

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the CLI script executable (optional):
```bash
chmod +x anker_prime_cli.py
```

## Usage

### Scan for Devices

```bash
python3 anker_prime_cli.py scan
```

Example output:
```
Found 2 device(s):

1. ASHDJW61F44302074
   Address: 7C:E9:13:65:4D:12
   RSSI: -65 dBm

2. AFYDKPN0F43501458
   Address: 7C:E9:13:5E:B8:64
   RSSI: -72 dBm
```

### Get Device Information

```bash
# Connect to first found device
python3 anker_prime_cli.py info

# Connect to specific device
python3 anker_prime_cli.py info --address 7C:E9:13:65:4D:12
```

Example output:
```
Device Information:
==================================================
Version: v0.0.3.7
Serial: ASHDJW61F44302074
Mac: 7C:E9:13:65:4D:12:36:31:46:34:34:33:30:32:30:37:34
```

### Get Device Status

```bash
# Get status with 10s monitoring
python3 anker_prime_cli.py status

# Specify device and monitoring time
python3 anker_prime_cli.py status --address 7C:E9:13:65:4D:12 --monitor-time 30
```

### Real-time Monitoring

```bash
# Monitor with 5s update interval
python3 anker_prime_cli.py monitor

# Custom interval
python3 anker_prime_cli.py monitor --interval 2.0

# Monitor specific device
python3 anker_prime_cli.py monitor --address 7C:E9:13:65:4D:12 --interval 10
```

Press `Ctrl+C` to stop monitoring.

## Configuration

You can customize the behavior by modifying constants in `anker_prime.py`:

```python
# Service UUIDs (change if your device uses different UUIDs)
SERVICE_UUID = "8c850001-0302-41c5-b46e-cf057c562025"
WRITE_CHAR_UUID = "8c850002-0302-41c5-b46e-cf057c562025"
NOTIFY_CHAR_UUID = "8c850003-0302-41c5-b46e-cf057c562025"

# Protocol constants
A2_STATIC_VALUE_HEX = "32633337376466613039636462373932343838396534323932613337663631633863356564353264"
```

## Development

### Project Structure

```
anker-vibecoded/
├── anker_prime.py          # Core library with protocol implementation
├── anker_prime_cli.py      # Command-line interface
├── requirements.txt        # Python dependencies
├── README.md              # This file
└── .gitignore             # Git ignore rules
```

### Library Usage

You can also use the library directly in your Python code:

```python
from anker_prime import AnkerCharger, scan_for_anker
import asyncio

async def main():
    # Scan for devices
    devices = await scan_for_anker()

    if devices:
        # Connect to first device
        charger = AnkerCharger(devices[0].address)

        try:
            await charger.connect()
            await charger.perform_handshake()

            print(f"Connected to: {charger.device_info['serial']}")
            print(f"Firmware: {charger.device_info['version']}")

            # Setup encryption and get status
            await charger.perform_initial_encryption()
            await charger.wait_for_session_key()
            await charger.perform_get_status()

        finally:
            await charger.disconnect()

asyncio.run(main())
```

### Protocol Details

The tool implements the Anker Prime BLE protocol:

1. **Handshake**: Unencrypted command exchange to get device info
2. **Initial Encryption**: AES-CBC with static key and serial number as IV
3. **Session Key**: Device sends 16-byte session key
4. **Encrypted Commands**: All status requests use session key encryption

Command examples:
- `0x0500`: Comprehensive status (battery, ports, power)
- `0x050E`: Live power status updates
- `0x0522`: Temperature reading

### Adding New Commands

To add new commands, extend the `AnkerCharger` class:

```python
async def perform_custom_command(self):
    """Send a custom command"""
    await self.send_encrypted_command(0x11, 0xYOUR_CMD, [
        {'type': 0xA1, 'value': bytes([0x21])}
    ])
    response = await self.notification_queue.get()
    self.parse_status_response(response)
```

## Troubleshooting

### No devices found
- Ensure Bluetooth is enabled: `bluetoothctl power on`
- Make sure the power bank is nearby and not connected to other devices
- Try scanning with bluetoothctl first: `bluetoothctl scan on`

### Connection fails
- Check if another application is connected to the device
- Try resetting Bluetooth: `sudo systemctl restart bluetooth`
- Ensure you have proper permissions to access Bluetooth

### Permission denied
- Add your user to the `bluetooth` group:
  ```bash
  sudo usermod -a -G bluetooth $USER
  ```
- Log out and back in for changes to take effect

### Minimal telemetry data
- Older firmware versions (pre-1.0) may not support comprehensive telemetry
- Try connecting a device to the power bank to trigger status updates
- Some models may have limited telemetry features

## References

- [Anker Prime BLE Hacking](https://github.com/atc1441/Anker_Prime_BLE_hacking) - Original research
- Web BLE implementation in `../AnkerPrimeWebBle.html`

## License

MIT License - see repository root for details

## Contributing

Contributions welcome! Please:
1. Test your changes with actual hardware
2. Update documentation for new features
3. Follow existing code style
4. Add examples for new commands

## Disclaimer

This tool is for educational and research purposes. Use at your own risk. The authors are not responsible for any damage to your devices.
