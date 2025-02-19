import asyncio
import os
from bleak import BleakClient, BleakScanner
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- Global Constants and Dictionaries ---

CHAR_UUID_WRITE = "feb5"
CHAR_UUID_NOTIFY = "feb6"
BASE_AES_KEY = bytes([
    0x3A, 0x60, 0x43, 0x2A, 0x5C, 0x01, 0x21, 0x1F,
    0x29, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

# Global variables for key exchange and encryption
terminal_public_key_bytes = None
aes_key = None

# Dictionary mapping CAN data field IDs (as 4-digit hex strings) to their details.
can_data_fields = {
    "F004": {"length": 2, "name": "Velocidade do Motor", "unit": "rpm", "formula": lambda x: x * 0.125},
    "FEF1": {"length": 2, "name": "Velocidade Baseada na Roda", "unit": "km/h", "formula": lambda x: x / 256},
    "FECA": {"length": 1, "name": "Indicador de Falha", "unit": "", "formula": lambda x: "ON" if x == 1 else "OFF"},
    "FEEC": {"length": 17, "name": "Número de Identificação do Veículo", "unit": "", "formula": None},
    "FEE0": {"length": 4, "name": "Distância Total do Veículo", "unit": "km", "formula": lambda x: x * 0.125},
    "E004": {"length": 1, "name": "Modo de Torque do Motor", "unit": "", "formula": lambda x: x},
    "F003": {"length": 1, "name": "Percentual de Carga do Motor", "unit": "%", "formula": lambda x: x},
    "FEF6": {"length": 1, "name": "Pressão do Turbo do Motor", "unit": "kPa", "formula": lambda x: x * 2},
    "FEEE": {"length": 1, "name": "Temperatura do Refrigerante do Motor", "unit": "ºC", "formula": lambda x: x - 40},
    "FEE9": {"length": 4, "name": "Total de Combustível Usado (Diesel)", "unit": "L", "formula": lambda x: x * 0.5},
    "FEFC": {"length": 1, "name": "Nível de Combustível 1", "unit": "%", "formula": lambda x: x * 0.4},
    "E003": {"length": 1, "name": "Posição do Pedal do Acelerador 1", "unit": "%", "formula": lambda x: x * 0.4},
    "FEF2": {"length": 1, "name": "Posição da Válvula do Acelerador 1", "unit": "%", "formula": lambda x: x * 0.4},
    "F00A": {"length": 2, "name": "Taxa de Fluxo de Massa do Ar de Entrada do Motor", "unit": "kg/h", "formula": lambda x: x * 0.05},
    "FEF5": {"length": 1, "name": "Pressão Barométrica", "unit": "kPa", "formula": lambda x: x * 0.5},
    "EEF1": {"length": 1, "name": "Estado do Governador PTO", "unit": "", "formula": lambda x: x},
    "FEC1": {"length": 4, "name": "Distância Total do Veículo (Alta Resolução)", "unit": "km", "formula": lambda x: x * 0.005},
    "FDB8": {"length": 2, "name": "Tempo Desde o Início do Motor", "unit": "s", "formula": lambda x: x},
    "EEF6": {"length": 1, "name": "Temperatura do Coletor de Admissão", "unit": "ºC", "formula": lambda x: x - 40},
    "E002": {"length": 1, "name": "Percentual de Torque Atual do Motor", "unit": "%", "formula": lambda x: x - 125},
    "FEE5": {"length": 4, "name": "Horas Totais de Operação do Motor", "unit": "hr", "formula": lambda x: x * 0.05},
    "0530": {"length": 2, "name": "Voltagem", "unit": "mV", "formula": lambda x: x},
    "0127": {"length": 4, "name": "Tempo de motor ligado", "unit": "s", "formula": lambda x: x},
    "0546": {"length": 4, "name": "Odometro Acumulado", "unit": "Km", "formula": lambda x: x/10},
}

# --- Cryptography and ECDH Functions ---

def generate_ecdh_keys():
    """Generate an ECDH key pair using a 2-byte random scalar and a custom generator."""
    rand = int.from_bytes(os.urandom(2), byteorder="big")
    G = int.from_bytes(b'\x83\xA5', byteorder='big')
    public_key = rand * G
    public_key_bytes = public_key.to_bytes(4, byteorder="big")
    return rand, public_key_bytes

def derive_custom_shared_secret(rand, peer_public_bytes):
    """Derive the shared secret using the custom generator point G."""
    peer_public_int = int.from_bytes(peer_public_bytes, byteorder='big')
    shared_secret = peer_public_int * rand
    shared_secret_bytes = shared_secret.to_bytes(6, byteorder="big", signed=False)[-6:]
    return shared_secret_bytes

def decrypt_data(encrypted_data, aes_key):
    """Decrypt packet data with AES-128 in ECB mode."""
    cipher = AES.new(aes_key, AES.MODE_ECB)
    if len(encrypted_data) != AES.block_size:
        print(f"Error: Encrypted data length {len(encrypted_data)} is not 16 bytes.")
        return None
    return cipher.decrypt(encrypted_data)

def encrypt_data(data, aes_key):
    """Encrypt packet data with AES-128 in ECB mode."""
    cipher = AES.new(aes_key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

async def send_data(client, char_uuid, data):
    await client.write_gatt_char(char_uuid, data)

# --- CAN Message Parser ---

def parse_can_message(msg: bytes):
    """
    Parse and print a CAN message according to the protocol.
    The CAN message may be prefixed with an extra header:
      B3 07 ?? ??
    If the first two bytes are B3 07, then skip the first 4 bytes so that parsing starts at F0.
    """
    # Check for the extra header starting with B3 07
    if len(msg) >= 4 and msg[:2] == b'\xB3\x07':
        print("Found extra header starting with 'B3 07'. Skipping the first 4 bytes.")
        msg = msg[4:]
    
    if len(msg) < 10:
        print("Message too short to parse CAN header.")
        return
    if msg[0] != 0xF0:
        print("Not a CAN message (header does not start with F0).")
        return

    # Parse header

    # --- Decode Timestamp as BCD ---
    # The next 6 bytes (indices 1-6) are the timestamp in BCD.
    timestamp_raw = msg[1:7]
    # Convert each byte into two BCD digits.
    timestamp_str = ''.join(f"{(b >> 4) & 0xF}{b & 0xF}" for b in timestamp_raw)
    # Expecting a 12-digit string: ddMMyyHHMMSS
    if len(timestamp_str) == 12:
        day   = timestamp_str[0:2]
        month = timestamp_str[2:4]
        year  = timestamp_str[4:6]
        hour  = timestamp_str[6:8]
        minute= timestamp_str[8:10]
        second= timestamp_str[10:12]
        formatted_timestamp = f"{day}/{month}/20{year} {hour}:{minute}:{second}"
    else:
        formatted_timestamp = timestamp_str

    data_type   = msg[7]
    vehicle_type= msg[8]
    subcategory = msg[9]

    data_type_str = {0x00: "Real Time", 0x01: "Stored"}.get(data_type, f"Unknown ({data_type})")
    vehicle_type_str = {0x01: "Commercial", 0x02: "Passenger"}.get(vehicle_type, f"Unknown ({vehicle_type})")

    print("\n=== CAN Message Header ===")
    print(f"Message Type: F0")
    print(f"Timestamp: {formatted_timestamp}")
    print(f"Data Type: {data_type_str} (0x{data_type:02X})")
    print(f"Vehicle Type: {vehicle_type_str} (0x{vehicle_type:02X})")

    if subcategory == 0x01:
        print("Subcategoria: Fluxo de Dados (Real-time data)")
        count = msg[10]
        print(f"Number of Data Flows: {count}")
        offset = 11
        while offset < len(msg):
            if offset + 3 > len(msg):
                print("Insufficient data for next field header.")
                break
            # Each field: 2-byte ID, 1-byte length, then the data bytes
            field_id_bytes = msg[offset:offset+2]
            field_id = field_id_bytes.hex().upper().zfill(4)
            field_length = msg[offset+2]
            offset += 3
            if offset + field_length > len(msg):
                print(f"Not enough data for field {field_id}. Expected length {field_length}.")
                break
            field_data = msg[offset:offset+field_length]
            offset += field_length

            if field_id in can_data_fields:
                field_info = can_data_fields[field_id]
                print(f"\nField ID: {field_id}")
                print(f"Name: {field_info['name']}")
                print(f"Raw Data: {field_data.hex().upper()}")
                if field_info["formula"] is not None:
                    value = int.from_bytes(field_data, byteorder="big")
                    computed_value = field_info["formula"](value)
                    print(f"Computed Value: {computed_value} {field_info['unit']}")
                else:
                    text = field_data.decode('ascii', errors='replace')
                    print(f"Text: {text}")
            else:
                print(f"\nField ID: {field_id} (Unknown)")
                print(f"Raw Data: {field_data.hex().upper()}")
    elif subcategory == 0x02:
        print("Subcategoria: Códigos de Falha (Fault Codes)")
        fault_data = msg[10:]
        print("Fault Codes Data (hex):", fault_data.hex().upper())
    elif subcategory == 0x0B:
        print("Subcategoria: Código VIN")
        if len(msg) < 11 + 1 + 17:
            print("Not enough data for VIN message.")
        else:
            vin_support = msg[10]
            vin_code = msg[11:11+17].decode('ascii', errors='replace')
            print(f"VIN Support: {vin_support} ({'Supported' if vin_support == 1 else 'Not Supported'})")
            print(f"VIN: {vin_code}")
    else:
        print(f"Unknown subcategory: 0x{subcategory:02X}")
        remaining = msg[10:]
        print("Remaining Data:", remaining.hex().upper())


# --- Notification Handler ---

async def receive_notification(client, sender, data):
    global terminal_public_key_bytes, aes_key
    print("\nReceived notification:", " ".join(f"{b:02X}" for b in data))

    # AES key confirmation response
    if data[:4] == b'\x42\x54\x55\x05':
        print(f"aes_key: {aes_key.hex()}")
        encrypted_payload = data[4:]
        if len(encrypted_payload) != AES.block_size:
            print(f"Error: Encrypted payload length {len(encrypted_payload)} is not 16 bytes.")
            return
        print("Encrypted payload:", " ".join(f"{b:02X}" for b in encrypted_payload))
        decrypted_payload = decrypt_data(encrypted_payload, aes_key)
        print("Decrypted payload:", " ".join(f"{b:02X}" for b in decrypted_payload))

    # Key exchange response
    if data[:4] == b'\x42\x54\x11\x01':
        print("Key exchange response detected.")
        terminal_public_key_bytes = data[8:12]
        print(f"Extracted terminal public key bytes: {terminal_public_key_bytes.hex().upper()}")

    # OBD data response (contains the encrypted CAN message)
    if data[:4] == b'\x42\x54\x5a\x01':
        print("OBD data response detected.")
        encrypted_data = data[4:]
        if len(encrypted_data) % AES.block_size != 0:
            print(f"Error: Encrypted data length {len(encrypted_data)} is not a multiple of 16 bytes.")
            return
        full_decrypted = b""
        for i in range(0, len(encrypted_data), AES.block_size):
            chunk = encrypted_data[i:i+AES.block_size]
            decrypted_chunk = decrypt_data(chunk, aes_key)
            if decrypted_chunk is None:
                return
            full_decrypted += decrypted_chunk
        print("Decrypted CAN message (hex):", full_decrypted.hex().upper())
        parse_can_message(full_decrypted)

# --- Device Scanning and Service Display ---

async def select_device():
    """Scan for Bluetooth devices and let the user select one."""
    print("Scanning for Bluetooth devices...")
    idxfinded = -2
    devices = await BleakScanner.discover()
    if not devices:
        print("No Bluetooth devices found. Exiting.")
        return None
    print("Available Bluetooth devices:")
    for idx, device in enumerate(devices):
        name = device.name or "Unknown"
        print(f"{idx}: {name} - {device.address}")
        if 'KD031' in name:
            idxfinded = idx
    
    while True:
        print(idxfinded)
        selection = idxfinded
        if idxfinded != -2: 
            try:
                index = int(selection)
                if 0 <= index < len(devices):
                    return devices[index].address
                else:
                    print("Device not found")
            except ValueError:
                print("Please enter a valid number.")
        else:
            print("Device not found")
            return 

async def display_services(client):
    """Retrieve and display the services and characteristics of the connected device."""
    print("\nRetrieving services and characteristics...")
    services = await client.get_services()
    for service in services:
        print(f"\nService: {service.uuid} - {service.description}")
        for char in service.characteristics:
            props = ", ".join(char.properties)
            print(f"  Characteristic: {char.uuid} - Properties: {props}")

# --- Main Function ---

async def main():
    global terminal_public_key_bytes, aes_key

    device_address = await select_device()
    if device_address is None:
        return

    async with BleakClient(device_address, disconnected_callback=lambda client: print("Disconnected from device")) as client:
        print("\nConnected to Bluetooth device.")
        await display_services(client)

        await client.start_notify(CHAR_UUID_NOTIFY,
                                  lambda sender, data: asyncio.create_task(receive_notification(client, sender, data)))

        print("\nStarting key exchange...")
        private_key, public_key_bytes = generate_ecdh_keys()
        key_exchange_packet = (
            bytes([0x42, 0x54, 0x11, 0x01, 0x89, 0x00, 0xC2, 0x00]) +
            public_key_bytes +
            bytes([0x00] * 8)
        )
        await send_data(client, CHAR_UUID_WRITE, key_exchange_packet)

        for _ in range(10):
            await asyncio.sleep(1)
            if terminal_public_key_bytes:
                print("Terminal public key received.")
                break
        else:
            print("Failed to receive terminal public key.")
            return

        try:
            shared_secret = derive_custom_shared_secret(private_key, terminal_public_key_bytes)
            aes_key = BASE_AES_KEY[:-6] + shared_secret
            print(f"AES key derived successfully.\nShared secret length: {len(shared_secret)} bytes, aes_key length: {len(aes_key)} bytes")
        except Exception as e:
            print(f"Error deriving shared secret: {e}")
            return

        imei_data = bytes([0x31] * 15)  # 15 bytes of '1' (0x31)
        start_and_type = b"\x42\x54\x22\x02"
        imei_data_encrypted = encrypt_data(imei_data, aes_key)
        encrypted_packet = start_and_type + imei_data_encrypted
        print(f"Encrypted IMEI packet: {encrypted_packet.hex().upper()}")
        try:
            await client.write_gatt_char(CHAR_UUID_WRITE, encrypted_packet, response=False)
            print("Encrypted IMEI sent for authentication.")
        except Exception as e:
            print(f"Failed to send encrypted IMEI: {e}")

        data_to_encrypt = bytes([0xc2, 0x06, 0x00, 0x00]) + bytes([0x00] * 12)
        encrypted_data = encrypt_data(data_to_encrypt, aes_key)
        await send_data(client, CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x5a, 0x01]) + encrypted_data)

        print("\nWaiting for further commands or notifications. Press Ctrl+C to exit.")
        while True:
            await asyncio.sleep(4)

if __name__ == "__main__":
    asyncio.run(main())