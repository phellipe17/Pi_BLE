import asyncio
import os
from bleak import BleakClient
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# Device address and characteristics
DEVICE_ADDRESS = "CB:59:2E:9F:76:11"
# CHAR_UUID_WRITE = "feb5"
# CHAR_UUID_NOTIFY = "feb6"
CHAR_UUID_WRITE = "0000feb5-0000-1000-8000-00805f9b34fb"
CHAR_UUID_NOTIFY = "0000feb6-0000-1000-8000-00805f9b34fb"
BASE_AES_KEY = bytes([0x3A, 0x60, 0x43, 0x2A, 0x5C, 0x01, 0x21, 0x1F, 0x29, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

# Store the received public key
terminal_public_key_bytes = None
aes_key = None


def generate_ecdh_keys():
    """Generate an ECDH key pair using a 2-byte random scalar multiplier and custom generator G."""
    # Generate a 2-byte random integer `rand`
    rand = int.from_bytes(os.urandom(2), byteorder="big")
    # Custom generator point G
    G = int.from_bytes(b'\x83\xA5', byteorder='big')
    # Calculate the public key as `public_key = rand * G`
    public_key = rand * G

    # Truncate to 4 bytes for transmission as required by protocol
    public_key_bytes = public_key.to_bytes(4, byteorder="big")
    return rand, public_key_bytes

def derive_custom_shared_secret(rand, peer_public_bytes):
    """Calculate the shared secret using the custom generator point G."""
    # Convert peer public key bytes to integer
    peer_public_int = int.from_bytes(peer_public_bytes, byteorder='big')
    # Derive the shared secret as S = peer_public_int * rand
    shared_secret = peer_public_int * rand
    # Get the last 6 bytes of the shared secret
    shared_secret_bytes = shared_secret.to_bytes(6, byteorder="big", signed=False)[-6:]
    return shared_secret_bytes


def decrypt_data(encrypted_data, aes_key):
    """Decrypt packet data with AES-128 in ECB mode."""
    cipher = AES.new(aes_key, AES.MODE_ECB)
    if len(encrypted_data) != AES.block_size:
        print(f"Error: Encrypted data length {len(encrypted_data)} is not 16 bytes.")
        return None
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

def encrypt_data(data, aes_key):
    """Encrypt packet data with AES-128 in ECB mode."""
    cipher = AES.new(aes_key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return encrypted_data

async def send_data(client, char_uuid, data):
    await client.write_gatt_char(char_uuid, data)
    
async def receive_notification(client, sender, data):
    global terminal_public_key_bytes
    global aes_key
    # print data in hex only and separated with spaces
    print("Received data:", " ".join(f"{b:02X}" for b in data))

    if data[:4] == b'\x42\x54\x55\x05':
        print(f"aes_key: {aes_key.hex()}")
        # decrypt the data using the derived AES key
        encrypted_data = data[4:]
        if len(encrypted_data) != AES.block_size:
            print(f"Error: Encrypted data length {len(encrypted_data)} is not 16 bytes.")
            return
        print("Encrypted data:", " ".join(f"{b:02X}" for b in encrypted_data))
        decrypted_data = decrypt_data(encrypted_data, aes_key)
        print(f"Decrypted data:", " ".join(f"{b:02X}" for b in decrypted_data))

    if data[:4] == b'\x42\x54\x11\x01':  # Key exchange response identifier
        print("Key exchange response detected.")
        terminal_public_key_bytes = data[8:12]  # Only 4 bytes for the public key as per protocol
        print(f"Extracted public key bytes: {terminal_public_key_bytes}")

    if data[:4] == b'\x42\x54\x5a\x01':  # OBD data response identifier
        print("OBD data response detected.")
        # get the data in chunks of 16 bytes and decrypt all of them
        encrypted_data = data[4:]
        if len(encrypted_data) % AES.block_size != 0:
            print(f"Error: Encrypted data length {len(encrypted_data)} is not a multiple of 16 bytes.")
            return
        for i in range(0, len(encrypted_data), AES.block_size):
            chunk = encrypted_data[i:i+AES.block_size]
            decrypted_data = decrypt_data(chunk, aes_key)
            print(f"Decrypted data chunk {i//AES.block_size}:", " ".join(f"{b:02X}" for b in decrypted_data))
        # acknowledge the data
        data_to_encrypt = bytes([0xb3, 0x00, 0x01, 0x00, 0x07]) + bytes([0x00] * 11)
        encrypted_data = encrypt_data(data_to_encrypt, aes_key)
        await send_data(client, CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x5a, 0x01]) + encrypted_data)


async def main():
    global terminal_public_key_bytes
    global aes_key

    async with BleakClient(DEVICE_ADDRESS, disconnected_callback=lambda client: print("Disconnected from device")) as client:
        print("Connected to Bluetooth device.")
        
        await asyncio.sleep(2)
        print("Listing available services and characteristics...")
        for service in client.services:
            print(f"Service: {service.uuid}")
            for char in service.characteristics:
                print(f"  Characteristic: {char.uuid}")

        # try:
        #     mtu_size = await client.exchange_mtu(512)  # Tenta configurar o MTU para 247 bytes
        #     print(f"MTU successfully negotiated to: {mtu_size} bytes")
        # except Exception as e:
        #     print(f"Failed to set MTU: {e}")
        
        # Start notifications
        
        await client.start_notify(CHAR_UUID_NOTIFY, lambda sender, data: asyncio.create_task(receive_notification(client, sender, data)))
        # await client.start_notify(CHAR_UUID_NOTIFY_LOG, receive_notification)

        # Key exchange
        print("Starting key exchange...")
        private_key, public_key_bytes = generate_ecdh_keys()
        await send_data(client, CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x11, 0x01, 0x89, 0x00, 0xC2, 0x00]) + public_key_bytes + bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

        # Wait for terminal's public key notification
        for _ in range(10):
            await asyncio.sleep(1)
            if terminal_public_key_bytes:
                print("Terminal public key received.")
                break
        else:
            print("Failed to receive terminal public key.")
            return

        # Derive the AES key
        try:
            shared_secret = derive_custom_shared_secret(private_key, terminal_public_key_bytes)
            aes_key = BASE_AES_KEY[:-6] + shared_secret
            print(f"AES key derived successfully. shared_secret length: {len(shared_secret)} bytes aes_key length: {len(aes_key)} bytes")
        except Exception as e:
            print(f"Error deriving shared secret: {e}")
            return

        # Encrypt the IMEI packet before sending
        imei_data = bytes([0x31] * 15)  # 15 bytes of '1' (0x31)
        # Define the packet structure
        start_and_type = b"\x42\x54\x22\x02"  # Start(2) and type(2)
        imei_data_encrypted = encrypt_data(imei_data, aes_key)  # Encrypt only the IMEI data

        encrypted_packet = start_and_type + imei_data_encrypted
        print(f"Encrypted IMEI packet: {encrypted_packet.hex()}")

        # Send the encrypted IMEI packet
        try:
            await client.write_gatt_char(CHAR_UUID_WRITE, encrypted_packet, response=False)
            print("Encrypted IMEI sent for authentication.")
        except Exception as e:
            print(f"Failed to send encrypted IMEI: {e}")

        # requests OBD data
        data_to_encrypt = bytes([0xc2, 0x06, 0x00, 0x00]) + bytes([0x00] * 12)
        encrypted_data = encrypt_data(data_to_encrypt, aes_key)
        await send_data(client, CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x5a, 0x01]) + encrypted_data)

        # Keep the connection open for additional interactions
        print("Waiting for further commands or notifications. Press Ctrl+C to exit.")
        while True:
            await asyncio.sleep(4)  # Keep the loop running to maintain the connection


asyncio.run(main())