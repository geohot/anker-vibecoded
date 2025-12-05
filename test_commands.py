#!/usr/bin/env python3
"""
Test different command/group combinations to find telemetry data
"""

import asyncio
from anker_prime import AnkerCharger, scan_for_anker

async def test_commands():
    devices = await scan_for_anker()
    if not devices:
        print("No devices found")
        return

    charger = AnkerCharger(devices[0].address)

    try:
        await charger.connect()
        await charger.perform_handshake()

        # Setup encryption
        await asyncio.sleep(0.5)
        await charger.perform_initial_encryption()
        await charger.wait_for_session_key()

        print("\n=== Testing Different Command Combinations ===\n")

        # Test different commands with different groups
        test_cases = [
            # (group, command, description)
            (0x01, 0x0500, "Group 0x01, Cmd 0x0500 (status)"),
            (0x01, 0x0D00, "Group 0x01, Cmd 0x0D00 (alt status)"),
            (0x11, 0x0D00, "Group 0x11, Cmd 0x0D00 (alt status encrypted)"),
            (0x11, 0x0001, "Group 0x11, Cmd 0x0001 (handshake encrypted)"),
            (0x11, 0x0029, "Group 0x11, Cmd 0x0029 (device info encrypted)"),
            (0x01, 0x050E, "Group 0x01, Cmd 0x050E (live power)"),
            (0x01, 0x0522, "Group 0x01, Cmd 0x0522 (temperature)"),
            (0x11, 0x0504, "Group 0x11, Cmd 0x0504 (set theme - read?)"),
            (0x11, 0x0505, "Group 0x11, Cmd 0x0505 (set beep - read?)"),
        ]

        for group, command, desc in test_cases:
            print(f"\nTrying: {desc}")
            print(f"  Group: 0x{group:02X}, Command: 0x{command:04X}")

            try:
                await charger.send_encrypted_command(group, command, [
                    {'type': 0xA1, 'value': bytes([0x21])}
                ])

                # Wait for response
                try:
                    response = await asyncio.wait_for(charger.notification_queue.get(), timeout=2.0)
                    charger.parse_status_response(response)
                except asyncio.TimeoutError:
                    print("  No response received")

            except Exception as e:
                print(f"  Error: {e}")

            await asyncio.sleep(0.5)

    finally:
        await charger.disconnect()

if __name__ == "__main__":
    asyncio.run(test_commands())
