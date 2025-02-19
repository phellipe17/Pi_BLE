import asyncio
import os
from bleak import BleakClient
from tinyec import registry
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import asyncio

# Device address and characteristics
# DEVICE_ADDRESS = "CB:59:2E:9F:76:11"
DEVICE_ADDRESS = 'C4:A8:28:3F:4F:41'
CHAR_UUID_WRITE = "feb5"
CHAR_UUID_NOTIFY = "feb6"
BASE_AES_KEY = bytes([0x3A, 0x60, 0x43, 0x2A, 0x5C, 0x01, 0x21, 0x1F, 0x29, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

DATA_TABLE ={
    "F004": {"length": 2, "name": "Engine Speed", "unit": "rpm", "formula": lambda x: x * 0.125},
    "FEF1": {"length": 2, "name": "Wheel-Based Vehicle Speed", "unit": "km/h", "formula": lambda x: x / 256},
    "FECA": {"length": 1, "name": "Malfunction Indicator Lamp", "unit": "", "formula": lambda x: "ON" if x == 1 else "OFF"},  # 1: ON, 0: OFF
    "FEE0": {"length": 4, "name": "Total Vehicle Distance", "unit": "km", "formula": lambda x: x * 0.125},
    "E004": {"length": 1, "name": "Engine Torque Mode", "unit": "", "formula": lambda x: x},
    "F003": {"length": 1, "name": "Engine Percent Load at Current Speed", "unit": "%", "formula": lambda x: x},
    "FEF6": {"length": 1, "name": "Engine Turbocharger Boost Pressure", "unit": "kPa", "formula": lambda x: x * 2},
    "FEEE": {"length": 1, "name": "Engine Coolant Temperature", "unit": "ºC", "formula": lambda x: x - 40},
    "FEE9": {"length": 4, "name": "Total Fuel Used (Diesel)", "unit": "L", "formula": lambda x: x * 0.5},
    "FEFC": {"length": 1, "name": "Fuel Level 1", "unit": "%", "formula": lambda x: x * 0.4},
    "E003": {"length": 1, "name": "Accelerator Pedal Position 1", "unit": "%", "formula": lambda x: x * 0.4},
    "FEF2": {"length": 1, "name": "Engine Throttle Valve Position 1", "unit": "%", "formula": lambda x: x * 0.4},
    "F00A": {"length": 2, "name": "Engine Intake Air Mass Flow Rate", "unit": "kg/h", "formula": lambda x: x * 0.05},
    "FEF5": {"length": 1, "name": "Barometric Pressure", "unit": "kPa", "formula": lambda x: x * 0.5},
    "EEF1": {"length": 1, "name": "PTO Governor State", "unit": "", "formula": lambda x: x},
    "FEC1": {"length": 4, "name": "High Resolution Total Vehicle Distance", "unit": "km", "formula": lambda x: x * 0.005},
    "FDB8": {"length": 2, "name": "Time Since Engine Start", "unit": "s", "formula": lambda x: x},
    "EEF6": {"length": 1, "name": "Intake Manifold Temperature", "unit": "ºC", "formula": lambda x: x - 40},
    "E002": {"length": 1, "name": "Actual Engine Percent Torque", "unit": "%", "formula": lambda x: x - 125},
    "FEE5": {"length": 4, "name": "Total Engine Hours of Operation", "unit": "hr", "formula": lambda x: x * 0.05},
    "FEEC": {"length": 17, "name": "Vehicle Identification Number (VIN)", "unit": "", "formula": lambda x: x.decode('ascii')},
}

# Store the received public key
terminal_public_key_bytes = None
aes_key = None
data_queue = asyncio.Queue(maxsize=100)  # Define um tamanho máximo para evitar acúmulo excessivo

async def process_data():
    global aes_key
    while True:
        data = await data_queue.get()  # Pega os dados da fila para processar
        try:
            encrypted_data = data[4:]
            decrypted_data = b""
            for i in range(0, len(encrypted_data), AES.block_size):
                chunk = encrypted_data[i:i+AES.block_size]
                decrypted_data += decrypt_data(chunk, aes_key)

            print(f"Decrypted data: {decrypted_data.hex()}")

            parsed_data = parse_obd_data(decrypted_data)
            for key, value in parsed_data.items():
                unit = next((info["unit"] for pid, info in DATA_TABLE.items() if info["name"] == key), "")
                print(f"{key}: {value} {unit}")
            print("---")
        except Exception as e:
            print(f"Erro ao processar dados: {e}")

def parse_obd_data(data):
    """
    Faz o parse dos dados OBD recebidos e retorna um dicionário com as informações.
    """
    # Calcula o comprimento total dos dados
    length = int.from_bytes(data[2:4][::-1], byteorder="big")  # Inverte e lê os bytes (big endian)

    print(f"OBD Data Length: {length}")

    # Separa os metadados e os dados reais
    obd_metadata_bytes = data[4:15]
    obd_data_bytes = data[15:4 + length]

    # Lê o tipo da mensagem
    message_type = obd_metadata_bytes[0]
    if message_type != 0xF0:
        print("Invalid message type")
        return {}

    date = obd_metadata_bytes[1:7]  # Data (ainda não processada)

    # Dados em tempo real ou armazenados
    is_data_real_time = obd_metadata_bytes[7] == 0x00

    # Tipo de veículo
    vehicle_type = obd_metadata_bytes[8]

    # Subtipo da mensagem (Stream de dados ou Código de falha)
    subtype = obd_metadata_bytes[9]

    # Número de fluxos de dados disponíveis
    number_of_informations_available = obd_metadata_bytes[10]

    current_start_byte = 0
    obd_data = {}

    print("LOOP")

    for _ in range(number_of_informations_available):
        # Lê o PID (ID de dados)
        pid = obd_data_bytes[current_start_byte:current_start_byte + 2].hex().upper()
        data_length = obd_data_bytes[current_start_byte + 2]

        # print("HEADER INFO")

        # Procura o PID na tabela de dados OBD
        obd_data_info = DATA_TABLE.get(pid)
        if not obd_data_info:
            current_start_byte += 3 + data_length
            continue

        # print(f"INFO: {obd_data_info}")

        # Extrai os valores brutos dos dados
        raw_value = obd_data_bytes[current_start_byte + 3:current_start_byte + 3 + data_length]
        
        # Aplica a fórmula para cálculo, exceto para ID específico "FEEC"
        if pid != "FEEC":
            value = obd_data_info["formula"](int.from_bytes(raw_value, byteorder="big"))
        else:
            value = raw_value.decode("ascii", errors="ignore")  # Decodifica como ASCII

        # print(f"VALUE: {value}")

        # Adiciona os dados processados ao dicionário
        obd_data[obd_data_info["name"]] = value

        # Avança para o próximo conjunto de dados
        current_start_byte += 3 + data_length

    return obd_data


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
        
        # 🟢 Monitoramento da fila para evitar sobrecarga
        if data_queue.qsize() >= 90:  
            print("Fila cheia! Descartando mensagens antigas...")
            _ = await data_queue.get()  # Remove a mensagem mais antiga para liberar espaço

        # 🟢 Bufferiza os dados para processamento posterior
        await data_queue.put(data)
        print(f"Tamanho da fila: {data_queue.qsize()}")
        
        # # get the data in chunks of 16 bytes and decrypt all of them
        # encrypted_data = data[4:]
        # if len(encrypted_data) % AES.block_size != 0:
        #     print(f"Error: Encrypted data length {len(encrypted_data)} is not a multiple of 16 bytes.")
        #     return
        # #Processa cada bloco de 16 bytes
        # decrypted_data = b""
        # for i in range(0, len(encrypted_data), AES.block_size):
        #     chunk = encrypted_data[i:i+AES.block_size]
        #     decrypted_data += decrypt_data(chunk, aes_key)
        #     print(f"Decrypted data chunk {i//AES.block_size}:", " ".join(f"{b:02X}" for b in decrypted_data))
        # # acknowledge the data
        # data_to_encrypt = bytes([0xb3, 0x00, 0x01, 0x00, 0x07]) + bytes([0x00] * 11)
        # encrypted_data = encrypt_data(data_to_encrypt, aes_key)
        # await send_data(client, CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x5a, 0x01]) + encrypted_data)
        
        # #Chama a nova função parse_obd_data
        # parsed_data = parse_obd_data(decrypted_data)
        # for key, value in parsed_data.items():
        #     unit = next((info["unit"] for pid, info in DATA_TABLE.items() if info["name"] == key), "")
        #     print(f"{key}: {value} {unit}")
        # print("---")


async def main():
    global terminal_public_key_bytes
    global aes_key

    async with BleakClient(DEVICE_ADDRESS, disconnected_callback=lambda client: print("Disconnected from device")) as client:
        print("Connected to Bluetooth device.")
        
        # Iniciar processamento da fila em paralelo
        asyncio.create_task(process_data())
        
        # Start notifications
        await client.start_notify(CHAR_UUID_NOTIFY, lambda sender, data: asyncio.create_task(receive_notification(client, sender, data)))
        # await client.start_notify(CHAR_UUID_NOTIFY_LOG, receive_notification)

        # Key exchange
        # print("Starting key exchange...")
        # private_key, public_key_bytes = generate_ecdh_keys()
        # await send_data(client, CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x11, 0x01, 0x89, 0x00, 0xC2, 0x00]) + public_key_bytes + bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

        print("Starting key exchange...")
        private_key, public_key_bytes = generate_ecdh_keys()
        try:
            await asyncio.wait_for(
                client.write_gatt_char(CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x11, 0x01, 0x89, 0x00, 0xC2, 0x00]) + public_key_bytes + bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            print("Timeout ao enviar chave pública.")
            return
        
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
        # try:
        #     await client.write_gatt_char(CHAR_UUID_WRITE, encrypted_packet, response=False)
        #     print("Encrypted IMEI sent for authentication.")
        # except Exception as e:
        #     print(f"Failed to send encrypted IMEI: {e}")
        
        try:
            await asyncio.wait_for(
                client.write_gatt_char(CHAR_UUID_WRITE, encrypted_packet, response=False),
                timeout=5.0
            )
            print("Encrypted IMEI sent for authentication.")
        except asyncio.TimeoutError:
            print("Timeout ao enviar IMEI criptografado.")
            return

        # requests OBD data
        # data_to_encrypt = bytes([0xc2, 0x06, 0x00, 0x00]) + bytes([0x00] * 12)
        # encrypted_data = encrypt_data(data_to_encrypt, aes_key)
        # await send_data(client, CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x5a, 0x01]) + encrypted_data)
        
        data_to_encrypt = bytes([0xc2, 0x06, 0x00, 0x00]) + bytes([0x00] * 12)
        encrypted_data = encrypt_data(data_to_encrypt, aes_key)
        try:
            await asyncio.wait_for(
                client.write_gatt_char(CHAR_UUID_WRITE, bytes([0x42, 0x54, 0x5a, 0x01]) + encrypted_data),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            print("Timeout ao solicitar dados OBD.")
            return

        # Keep the connection open for additional interactions
        print("Waiting for further commands or notifications. Press Ctrl+C to exit.")
        while True:
            await asyncio.sleep(4)  # Keep the loop running to maintain the connection


asyncio.run(main())