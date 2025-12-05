#!/usr/bin/env python3
"""
Anker Charger BLE Connection Script
Based on the protocol from AnkerPrimeWebBle.html
"""

import asyncio
import struct
import time
from bleak import BleakClient, BleakScanner
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Service and Characteristic UUIDs (for the ASHDJW model)
SERVICE_UUID = "8c850001-0302-41c5-b46e-cf057c562025"
WRITE_CHAR_UUID = "8c850002-0302-41c5-b46e-cf057c562025"
NOTIFY_CHAR_UUID = "8c850003-0302-41c5-b46e-cf057c562025"

# Protocol constants from the Web BLE code
A2_STATIC_VALUE_HEX = "32633337376466613039636462373932343838396534323932613337663631633863356564353264"
INITIAL_ENCRYPTION_KEY_HEX = A2_STATIC_VALUE_HEX[:32]

class AnkerCharger:
    def __init__(self, address):
        self.address = address
        self.client = None
        self.active_key = None
        self.active_iv = None
        self.crypto_state = "INACTIVE"
        self.device_info = {}
        self.session_timestamp_bytes = None
        self.notification_queue = asyncio.Queue()

    def calculate_checksum(self, data):
        """Calculate XOR checksum"""
        checksum = 0
        for byte in data:
            checksum ^= byte
        return checksum

    def build_tlv(self, tlv_array):
        """Build TLV (Type-Length-Value) buffer"""
        buffer = bytearray()
        for item in tlv_array:
            buffer.append(item['type'])
            buffer.append(len(item['value']))
            buffer.extend(item['value'])
        return bytes(buffer)

    def build_request(self, command, tlv_array, group=0x01):
        """Build command request packet"""
        command_high = (command >> 8) & 0xFF
        command_low = command & 0xFF

        command_header = bytes([0x03, 0x00, group, command_high])
        command_code = bytes([command_low])
        tlv_data = self.build_tlv(tlv_array)

        payload = command_header + command_code + tlv_data
        return payload

    async def send_raw_payload(self, payload):
        """Send raw payload with proper framing and checksum"""
        total_packet_length = len(payload) + 5

        # Build message for checksum calculation
        message = bytearray([0xFF, 0x09])
        message.extend(struct.pack('<H', total_packet_length))
        message.extend(payload)

        checksum = self.calculate_checksum(message)
        final_message = bytes(message) + bytes([checksum])

        print(f"[TX] {final_message.hex()}")
        await self.client.write_gatt_char(WRITE_CHAR_UUID, final_message, response=False)

    def notification_handler(self, sender, data):
        """Handle incoming notifications"""
        print(f"[RX] {data.hex()}")

        # Check for session key in encrypted responses (TLV type 0xA1 with 16 bytes)
        if self.crypto_state == 'Initial' and len(data) > 20:
            # Try to decrypt and look for session key
            try:
                if len(data) >= 9 and (data[7] & 0x40):  # Encrypted response
                    ciphertext = data[9:-1]
                    plaintext = self.decrypt(ciphertext)
                    print(f"[RX-DECRYPTED] {plaintext.hex()}")

                    # Parse TLV for session key
                    i = 1 if (len(plaintext) > 0 and plaintext[0] == 0x00) else 0
                    while i < len(plaintext) - 1:
                        if i + 2 > len(plaintext):
                            break
                        tlv_type = plaintext[i]
                        tlv_length = plaintext[i + 1]
                        if i + 2 + tlv_length > len(plaintext):
                            break
                        value = plaintext[i + 2:i + 2 + tlv_length]

                        if tlv_type == 0xA1 and tlv_length == 16:
                            print("[CRYPTO] New session key received!")
                            # Use serial as IV (truncate/pad to 16 bytes)
                            serial_bytes = self.device_info['serial'].encode('utf-8')
                            if len(serial_bytes) < 16:
                                serial_iv = serial_bytes + b'\x00' * (16 - len(serial_bytes))
                            else:
                                serial_iv = serial_bytes[:16]
                            self.setup_crypto(value, serial_iv, 'Session')
                            break

                        i += 2 + tlv_length
            except Exception as e:
                print(f"[DEBUG] Error checking for session key: {e}")

        # Put the data in the queue for processing
        asyncio.create_task(self.notification_queue.put(data))

    async def connect(self):
        """Connect to the Anker charger"""
        print(f"Connecting to {self.address}...")
        self.client = BleakClient(self.address)
        await self.client.connect()
        print("Connected!")

        # Enable notifications
        await self.client.start_notify(NOTIFY_CHAR_UUID, self.notification_handler)
        print("Notifications enabled")

    async def disconnect(self):
        """Disconnect from the charger"""
        if self.client and self.client.is_connected:
            await self.client.disconnect()
            print("Disconnected")

    def setup_crypto(self, key_bytes, iv_bytes, state):
        """Setup encryption context"""
        self.active_key = key_bytes
        self.active_iv = iv_bytes
        self.crypto_state = state
        print(f"[CRYPTO] Context set to state '{state}'")
        print(f"[CRYPTO] Key: {self.active_key.hex()}")
        print(f"[CRYPTO] IV: {self.active_iv.hex()}")

    def encrypt(self, plaintext):
        """Encrypt data using AES-CBC"""
        # Pad to 16-byte boundary
        padded = pad(plaintext, 16)
        cipher = AES.new(self.active_key, AES.MODE_CBC, self.active_iv)
        return cipher.encrypt(padded)

    def decrypt(self, ciphertext):
        """Decrypt data using AES-CBC"""
        cipher = AES.new(self.active_key, AES.MODE_CBC, self.active_iv)
        decrypted = cipher.decrypt(ciphertext)
        return unpad(decrypted, 16)

    async def send_encrypted_command(self, group, command, tlv_array):
        """Send encrypted command"""
        if self.crypto_state not in ['Initial', 'Session']:
            raise Exception("Encryption requested but crypto not ready")

        command_high = (command >> 8) & 0xFF
        command_low = command & 0xFF
        final_command_high = command_high | 0x40  # Add encryption flag

        # Encrypt the TLV data
        tlv_data = self.build_tlv(tlv_array)
        ciphertext = self.encrypt(tlv_data)

        # Build final payload
        command_header = bytes([0x03, 0x00, group, final_command_high, command_low])
        final_payload = command_header + ciphertext

        await self.send_raw_payload(final_payload)

    async def perform_handshake(self):
        """Perform initial handshake"""
        print("\n=== Starting Handshake ===")

        # Get UTC timestamp
        utc_seconds = int(time.time())
        self.session_timestamp_bytes = struct.pack('<I', utc_seconds)

        # Command 0x0001
        print("Sending command 0x0001...")
        payload = self.build_request(0x0001, [
            {'type': 0xA1, 'value': self.session_timestamp_bytes},
            {'type': 0xA2, 'value': bytes.fromhex(A2_STATIC_VALUE_HEX)}
        ])
        await self.send_raw_payload(payload)
        response = await asyncio.wait_for(self.notification_queue.get(), timeout=5.0)

        # Command 0x0003
        print("Sending command 0x0003...")
        payload = self.build_request(0x0003, [
            {'type': 0xA1, 'value': self.session_timestamp_bytes},
            {'type': 0xA2, 'value': bytes.fromhex(A2_STATIC_VALUE_HEX)},
            {'type': 0xA3, 'value': bytes([0x20])},
            {'type': 0xA4, 'value': bytes([0x00, 0xF0])}
        ])
        await self.send_raw_payload(payload)
        response = await asyncio.wait_for(self.notification_queue.get(), timeout=5.0)

        # Command 0x0029 (get device info)
        print("Sending command 0x0029 (device info)...")
        payload = self.build_request(0x0029, [
            {'type': 0xA1, 'value': self.session_timestamp_bytes},
            {'type': 0xA2, 'value': bytes.fromhex(A2_STATIC_VALUE_HEX)}
        ])
        await self.send_raw_payload(payload)
        response = await asyncio.wait_for(self.notification_queue.get(), timeout=5.0)
        self.extract_device_info(response)

        # Command 0x0005
        print("Sending command 0x0005...")
        payload = self.build_request(0x0005, [
            {'type': 0xA1, 'value': self.session_timestamp_bytes},
            {'type': 0xA2, 'value': bytes.fromhex(A2_STATIC_VALUE_HEX)},
            {'type': 0xA3, 'value': bytes([0x20])},
            {'type': 0xA4, 'value': bytes([0x00, 0xF0])},
            {'type': 0xA5, 'value': bytes([0x02])}
        ])
        await self.send_raw_payload(payload)
        response = await asyncio.wait_for(self.notification_queue.get(), timeout=5.0)

        print("Handshake complete!")
        print(f"Device Info: {self.device_info}")

    async def perform_initial_encryption(self):
        """Setup initial encryption and send encrypted command 0x0022"""
        print("\n=== Setting up Initial Encryption ===")

        if not self.device_info.get('serial') or not self.session_timestamp_bytes:
            raise Exception("Missing serial number or timestamp for encryption")

        # Setup crypto with initial key and serial as IV (must be exactly 16 bytes)
        initial_key = bytes.fromhex(INITIAL_ENCRYPTION_KEY_HEX)
        serial_bytes = self.device_info['serial'].encode('utf-8')
        # Pad or truncate serial to 16 bytes
        if len(serial_bytes) < 16:
            serial_iv = serial_bytes + b'\x00' * (16 - len(serial_bytes))
        else:
            serial_iv = serial_bytes[:16]
        self.setup_crypto(initial_key, serial_iv, 'Initial')

        # Send encrypted command 0x0022
        print("Sending encrypted command 0x0022...")
        await self.send_encrypted_command(0x01, 0x0022, [
            {'type': 0xA1, 'value': self.session_timestamp_bytes},
            {'type': 0xA2, 'value': bytes.fromhex(A2_STATIC_VALUE_HEX)},
            {'type': 0xA3, 'value': bytes(4)},  # 4 zero bytes
            {'type': 0xA5, 'value': bytes(40)}   # 40 zero bytes
        ])

        print("Waiting for session key from device...")

    async def wait_for_session_key(self):
        """Wait for and process session key response"""
        max_attempts = 20
        for attempt in range(max_attempts):
            if self.crypto_state == 'Session':
                print("[SUCCESS] Session key established!")
                return True
            await asyncio.sleep(0.5)

        raise Exception("Timeout waiting for session key")

    async def perform_get_status(self):
        """Get device status (battery, power, etc.)"""
        print("\n=== Requesting Device Status ===")

        if self.crypto_state != 'Session':
            raise Exception("Session key not active, cannot get status")

        # Send encrypted status request (command 0x0500, group 0x11)
        print("Sending encrypted status request (0x0500)...")
        await self.send_encrypted_command(0x11, 0x0500, [
            {'type': 0xA1, 'value': bytes([0x21])}
        ])

        # Wait for ALL responses
        max_retries = 5
        for i in range(max_retries):
            try:
                response = await asyncio.wait_for(self.notification_queue.get(), timeout=2.0)
                # Check if this is a status response (command 0x0500, 0x0D00, etc.)
                if len(response) >= 9:
                    cmd_byte = response[7]
                    cmd_low = response[8]
                    full_cmd = ((cmd_byte & ~0x48) << 8) | cmd_low  # Mask out encryption and ACK flags
                    print(f"[DEBUG] Received response for command: 0x{full_cmd:04X} (raw: 0x{cmd_byte:02X}{cmd_low:02X})")
                    # Parse all encrypted responses
                    self.parse_status_response(response)
                    # Accept 0x0500 or 0x0D00 as main status responses
                    if full_cmd in [0x0500, 0x0D00, 0x050E, 0x0522]:
                        # Keep looking for more responses
                        continue
            except asyncio.TimeoutError:
                break  # No more responses
            await asyncio.sleep(0.1)

    def parse_status_response(self, payload):
        """Parse encrypted status response"""
        # Determine command type
        if len(payload) >= 9:
            command_high = payload[7]
            command_low = payload[8]
            full_cmd = ((command_high & ~0x48) << 8) | command_low
            print(f"\n[PARSE] Command 0x{full_cmd:04X}")

        # Check if encrypted (bit 0x40 in command high byte)
        if len(payload) >= 8:
            command_high = payload[7]
            is_encrypted = (command_high & 0x40) != 0

            if is_encrypted and self.active_key:
                # Ciphertext starts after header (skip first 9 bytes, last is checksum)
                ciphertext = payload[9:-1]
                try:
                    plaintext = self.decrypt(ciphertext)
                    print(f"[DECRYPTED] {plaintext.hex()} ({len(plaintext)} bytes)")
                    self.parse_status_tlv(plaintext)
                except Exception as e:
                    print(f"[ERROR] Decryption failed: {e}")
            else:
                print(f"[INFO] Response not encrypted or no key available")

    def parse_status_tlv(self, data):
        """Parse status TLV data"""
        print("\n=== Device Status ===")
        i = 1 if (len(data) > 0 and data[0] == 0x00) else 0  # Skip status code if present

        while i < len(data) - 1:
            if i + 2 > len(data):
                break

            tlv_type = data[i]
            tlv_length = data[i + 1]

            if i + 2 + tlv_length > len(data):
                break

            value = data[i + 2:i + 2 + tlv_length]

            # Parse different status types
            if tlv_type == 0xA2 and len(value) >= 10:  # Battery info
                battery_pct = f"{value[8]}.{value[9]:02d}"
                print(f"Battery Level: {battery_pct}%")
            elif tlv_type == 0xB3 and len(value) >= 3:  # Temperature
                temp_c = value[1]
                temp_f = value[2]
                print(f"Temperature: {temp_c}°C / {temp_f}°F")
            elif tlv_type == 0xAE and len(value) >= 5:  # Power
                total_out = struct.unpack('<H', value[1:3])[0] / 10.0
                total_in = struct.unpack('<H', value[3:5])[0] / 10.0
                print(f"Total Output: {total_out:.1f}W")
                print(f"Total Input: {total_in:.1f}W")
            elif tlv_type in [0xA4, 0xA5, 0xA6] and len(value) >= 12:  # Port info
                port_name = {0xA4: "USB-C 1", 0xA5: "USB-C 2", 0xA6: "USB-A"}[tlv_type]
                mode = {0: "Off", 1: "Input", 2: "Output"}.get(value[2], f"Unknown({value[2]})")

                if mode != "Off":
                    voltage = struct.unpack('<H', value[3:5])[0] / 10.0
                    current = struct.unpack('<H', value[5:7])[0] / 10.0
                    power = voltage * current
                    print(f"{port_name}: {mode} - {voltage:.2f}V, {current:.3f}A, {power:.2f}W")
                else:
                    print(f"{port_name}: {mode}")

            i += 2 + tlv_length

    def extract_device_info(self, payload):
        """Extract device information from TLV response"""
        # Skip the packet header (4 bytes) and command response (2 bytes)
        # Response format: [0xFF 0x09 length(2) | 0x03 0x00 group cmd_high cmd_low status | TLV data | checksum]
        # We need to skip: FF 09 (2) + length (2) + 03 00 group cmd_high cmd_low status (6) = 10 bytes to TLV start
        i = 10

        print(f"[DEBUG] Parsing device info from offset {i}, payload length: {len(payload)}")
        print(f"[DEBUG] Full payload: {payload.hex()}")

        while i < len(payload) - 1:  # -1 for checksum at end
            if i + 2 > len(payload):
                break

            tlv_type = payload[i]
            tlv_length = payload[i + 1]

            if i + 2 + tlv_length > len(payload):
                break

            value = payload[i + 2:i + 2 + tlv_length]

            print(f"[DEBUG] TLV Type: 0x{tlv_type:02X}, Length: {tlv_length}, Value: {value.hex()}")

            if tlv_type == 0xA3:  # Firmware version
                self.device_info['version'] = value.decode('utf-8', errors='ignore')
                print(f"[INFO] Firmware: {self.device_info['version']}")
            elif tlv_type == 0xA4:  # Serial number
                self.device_info['serial'] = value.decode('utf-8', errors='ignore')
                print(f"[INFO] Serial: {self.device_info['serial']}")
            elif tlv_type == 0xA5:  # MAC address
                self.device_info['mac'] = ':'.join(f'{b:02X}' for b in value)
                print(f"[INFO] MAC: {self.device_info['mac']}")

            i += 2 + tlv_length

async def scan_for_anker():
    """Scan for Anker chargers"""
    print("Scanning for Anker chargers...")
    devices = await BleakScanner.discover(timeout=10.0)

    anker_devices = []
    for device in devices:
        # Check for Anker devices by MAC prefix (Fantasia Trading LLC = 7C:E9:13)
        # or by device name patterns
        if (device.address.upper().startswith('7C:E9:13') or
            (device.name and ('ASHDJW' in device.name or 'AFYDKPN' in device.name or 'Anker' in device.name))):
            anker_devices.append(device)
            print(f"Found: {device.name} ({device.address})")

    return anker_devices

# Library-only file - use anker_prime_cli.py for command-line interface
