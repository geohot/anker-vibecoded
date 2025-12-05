#!/usr/bin/env python3
"""
Anker Prime BLE CLI Tool
Connect to and monitor Anker Prime power banks via Bluetooth LE
"""

import asyncio
import argparse
import sys
import json
from anker_prime import AnkerCharger, scan_for_anker

async def scan_command(args):
    """Scan for Anker chargers"""
    print("Scanning for Anker Prime chargers...")
    devices = await scan_for_anker()

    if not devices:
        print("No Anker devices found")
        return

    print(f"\nFound {len(devices)} device(s):\n")
    for idx, device in enumerate(devices, 1):
        print(f"{idx}. {device.name}")
        print(f"   Address: {device.address}")
        rssi = getattr(device, 'rssi', None)
        if rssi is not None:
            print(f"   RSSI: {rssi} dBm")
        print()

async def info_command(args):
    """Get device information"""
    if args.address:
        devices = [type('Device', (), {'address': args.address, 'name': 'Unknown'})]
    else:
        devices = await scan_for_anker()
        if not devices:
            print("No Anker devices found")
            return
        devices = [devices[0]]  # Use first device

    charger = AnkerCharger(devices[0].address)

    try:
        await charger.connect()
        await charger.perform_handshake()

        print("\nDevice Information:")
        print("=" * 50)
        for key, value in charger.device_info.items():
            print(f"{key.capitalize()}: {value}")

    finally:
        await charger.disconnect()

async def status_command(args):
    """Get device status"""
    if args.address:
        devices = [type('Device', (), {'address': args.address, 'name': 'Unknown'})]
    else:
        devices = await scan_for_anker()
        if not devices:
            print("No Anker devices found")
            return
        devices = [devices[0]]

    charger = AnkerCharger(devices[0].address)

    try:
        await charger.connect()
        await charger.perform_handshake()

        # Setup encryption
        await asyncio.sleep(0.5)
        await charger.perform_initial_encryption()
        await charger.wait_for_session_key()

        # Get status
        await asyncio.sleep(0.5)
        print("\nRequesting device status...")
        await charger.perform_get_status()

        # Monitor for updates
        print("Monitoring for telemetry updates...")
        for i in range(args.monitor_time):
            try:
                response = await asyncio.wait_for(charger.notification_queue.get(), timeout=1.0)
                if len(response) >= 9:
                    charger.parse_status_response(response)
            except asyncio.TimeoutError:
                pass

    finally:
        await charger.disconnect()

async def monitor_command(args):
    """Monitor device in real-time"""
    if args.address:
        devices = [type('Device', (), {'address': args.address, 'name': 'Unknown'})]
    else:
        devices = await scan_for_anker()
        if not devices:
            print("No Anker devices found")
            return
        devices = [devices[0]]

    charger = AnkerCharger(devices[0].address)

    try:
        await charger.connect()
        await charger.perform_handshake()

        # Setup encryption
        await asyncio.sleep(0.5)
        await charger.perform_initial_encryption()
        await charger.wait_for_session_key()

        print("\nMonitoring device... Press Ctrl+C to stop")
        print("=" * 50)

        # Continuous monitoring
        interval = args.interval
        while True:
            await charger.perform_get_status()

            # Check for updates
            try:
                response = await asyncio.wait_for(charger.notification_queue.get(), timeout=interval)
                charger.parse_status_response(response)
            except asyncio.TimeoutError:
                pass

            await asyncio.sleep(interval)

    except KeyboardInterrupt:
        print("\n\nMonitoring stopped")
    finally:
        await charger.disconnect()

def main():
    parser = argparse.ArgumentParser(
        description='Anker Prime BLE CLI Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan                          # Scan for devices
  %(prog)s info                          # Get device info (first found)
  %(prog)s info --address 7C:E9:13:65:4D:12  # Get info for specific device
  %(prog)s status                        # Get current status
  %(prog)s monitor --interval 5          # Monitor with 5s updates
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to run')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan for Anker devices')

    # Info command
    info_parser = subparsers.add_parser('info', help='Get device information')
    info_parser.add_argument('--address', '-a', help='Device MAC address')

    # Status command
    status_parser = subparsers.add_parser('status', help='Get device status')
    status_parser.add_argument('--address', '-a', help='Device MAC address')
    status_parser.add_argument('--monitor-time', '-t', type=int, default=10,
                             help='Time to monitor for updates (seconds, default: 10)')

    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Monitor device continuously')
    monitor_parser.add_argument('--address', '-a', help='Device MAC address')
    monitor_parser.add_argument('--interval', '-i', type=float, default=5.0,
                               help='Update interval in seconds (default: 5.0)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Run the appropriate command
    command_map = {
        'scan': scan_command,
        'info': info_command,
        'status': status_command,
        'monitor': monitor_command,
    }

    try:
        asyncio.run(command_map[args.command](args))
        return 0
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
