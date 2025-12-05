#!/usr/bin/env python3
"""
Test raw commands without TLV payloads and different parameter combinations
"""

import asyncio
from anker_prime import AnkerCharger, scan_for_anker

async def test_raw():
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

        print("\n=== Testing Commands with Different TLV Values ===\n")

        test_cases = [
            # Try empty TLV
            (0x11, 0x0500, [], "Empty TLV"),
            # Try different A1 values
            (0x11, 0x0500, [{'type': 0xA1, 'value': bytes([0x00])}], "A1=0x00"),
            (0x11, 0x0500, [{'type': 0xA1, 'value': bytes([0x01])}], "A1=0x01"),
            (0x11, 0x0500, [{'type': 0xA1, 'value': bytes([0x11])}], "A1=0x11"),
            (0x11, 0x0500, [{'type': 0xA1, 'value': bytes([0x20])}], "A1=0x20"),
            (0x11, 0x0500, [{'type': 0xA1, 'value': bytes([0x31])}], "A1=0x31"),
            # Try different TLV types
            (0x11, 0x0500, [{'type': 0xA2, 'value': bytes([0x21])}], "A2=0x21"),
            (0x11, 0x0500, [{'type': 0xA3, 'value': bytes([0x21])}], "A3=0x21"),
            # Try multiple TLVs
            (0x11, 0x0500, [
                {'type': 0xA1, 'value': bytes([0x21])},
                {'type': 0xA2, 'value': bytes([0x00])}
            ], "A1=0x21, A2=0x00"),
        ]

        for group, command, tlv_array, desc in test_cases:
            print(f"\nTrying 0x{group:02X}/0x{command:04X}: {desc}")

            try:
                await charger.send_encrypted_command(group, command, tlv_array)

                # Wait for response
                try:
                    response = await asyncio.wait_for(charger.notification_queue.get(), timeout=2.0)
                    if len(response) >= 9:
                        cmd_byte = response[7]
                        cmd_low = response[8]
                        is_encrypted = (cmd_byte & 0x40) != 0

                        if is_encrypted and charger.active_key:
                            ciphertext = response[9:-1]
                            plaintext = charger.decrypt(ciphertext)
                            print(f"  Response: {plaintext.hex()}")

                            # Look for any non-0x31 values
                            if plaintext.hex() != "00a10131":
                                print(f"  *** DIFFERENT RESPONSE! ***")
                                charger.parse_status_tlv(plaintext)
                except asyncio.TimeoutError:
                    print("  No response")

            except Exception as e:
                print(f"  Error: {e}")

            await asyncio.sleep(0.3)

    finally:
        await charger.disconnect()

if __name__ == "__main__":
    asyncio.run(test_raw())
