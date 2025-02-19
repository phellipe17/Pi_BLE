import asyncio
import os
from bleak import BleakClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 📌 Endereço Bluetooth do KD301
DEVICE_ADDRESS = "CB:59:2E:9F:76:11"

# 📌 Características Bluetooth do KD301
CHAR_UUID_WRITE = "0000feb5-0000-1000-8000-00805f9b34fb"
CHAR_UUID_NOTIFY = "0000feb6-0000-1000-8000-00805f9b34fb"

# 📌 Chave AES Base (antes da troca de chaves ECDH)
BASE_AES_KEY = bytes([0x3A, 0x60, 0x43, 0x2A, 0x5C, 0x01, 0x21, 0x1F, 
                      0x29, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

# 📌 Comandos do protocolo do KD301
CMD_KEY_EXCHANGE = bytes([0x42, 0x54, 0x11, 0x01, 0x89, 0x00, 0xC2, 0x00]) + bytes(8)  # Troca de chaves ECDH
CMD_SEND_IMEI = bytes([0x42, 0x54, 0x22, 0x02]) + bytes([0x31] * 15)  # Enviar IMEI '111111111111111'
CMD_REQUEST_OBD_INFO = bytes([0x42, 0x54, 0x5A, 0x01]) + bytes([0xC2, 0x06, 0x00, 0x00]) + bytes(12)  # Solicitação de OBD

# 📌 Dicionários para mapear baud rates e protocolos do KD301
BAUD_RATES = {
    0x00: "9600 bps", 0x01: "19200 bps", 0x02: "38400 bps",
    0x03: "57600 bps", 0x04: "115200 bps", 0x05: "230400 bps",
    0x06: "500000 bps", 0x07: "1000000 bps"
}

PROTOCOLS = {
    0x00: "SAE J1939", 0x01: "ISO 9141-2", 
    0x02: "ISO 14230-4 (KWP2000)", 0x03: "ISO 15765-4 (CAN Bus)"
}

# 📌 Variáveis globais para chaves
terminal_public_key_bytes = None
aes_key = None


def decrypt_data(encrypted_data):
    """Descriptografa os dados recebidos usando AES-128 ECB."""
    try:
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted_data
    except Exception as e:
        print(f"❌ Erro na decriptação: {e}")
        return None


def parse_device_info(data):
    """Analisa a resposta do dispositivo e identifica o baud rate e protocolo."""
    if len(data) < 4:
        print("❌ Resposta inválida ou incompleta.")
        return
    
    baud_rate_code = data[2]  # Byte 3 indica o baud rate
    protocol_code = data[3]  # Byte 4 indica o protocolo

    baud_rate = BAUD_RATES.get(baud_rate_code, "Desconhecido")
    protocol = PROTOCOLS.get(protocol_code, "Desconhecido")

    print(f"⚙️ Baud Rate do KD301: {baud_rate}")
    print(f"📡 Protocolo de Comunicação: {protocol}")


async def receive_notification(client, sender, data):
    """Recebe os dados enviados pelo dispositivo e processa."""
    global terminal_public_key_bytes, aes_key

    print(f"📥 Resposta Recebida ({sender}): {data.hex()}")

    if data[:4] == b'\x42\x54\x11\x01':  # Resposta da troca de chaves
        print("🔑 Chave pública do dispositivo recebida.")
        terminal_public_key_bytes = data[8:12]  # Captura os 4 bytes da chave pública

    elif data[:4] == b'\x42\x54\x55\x05':  # Resposta do IMEI
        print("✅ IMEI autenticado com sucesso.")
        print("📡 Solicitando informações do KD301...")
        encrypted_obd_request = AES.new(aes_key, AES.MODE_ECB).encrypt(pad(CMD_REQUEST_OBD_INFO[4:], AES.block_size))
        await client.write_gatt_char(CHAR_UUID_WRITE, CMD_REQUEST_OBD_INFO[:4] + encrypted_obd_request)

    elif data[:4] == b'\x42\x54\x5A\x01':  # Resposta do baud rate e protocolo
        encrypted_data = data[4:]
        decrypted_data = decrypt_data(encrypted_data)
        decrypt_data = decrypt_data(data[4:])
        if decrypted_data:
            print(f"🔓 Dados Decriptados: {decrypted_data.hex()}")
            parse_device_info(decrypted_data)
        else:
            print("❌ Falha ao decriptar os dados de baud rate e protocolo.")
        buffered_response = b""  # Reset após processamento


def generate_ecdh_keys():
    """Gera um par de chaves ECDH para a troca de chaves."""
    rand = int.from_bytes(os.urandom(2), byteorder="big")
    G = int.from_bytes(b'\x83\xA5', byteorder='big')  # Gerador fixo
    public_key = rand * G

    public_key_bytes = public_key.to_bytes(4, byteorder="big")
    return rand, public_key_bytes


async def get_device_info():
    """Conecta ao KD301, realiza a autenticação e exibe o baud rate e protocolo."""
    global terminal_public_key_bytes, aes_key

    async with BleakClient(DEVICE_ADDRESS) as client:
        if not client.is_connected:
            print("❌ Falha ao conectar ao KD301.")
            return

        print("✅ Conectado ao Jimi IoT KD301!")

        # 🟢 Ativar notificações para capturar dados
        try:
            await client.start_notify(CHAR_UUID_NOTIFY, lambda sender, data: asyncio.create_task(receive_notification(client, sender, data)))
            print("📡 Escutando respostas do dispositivo...")
        except Exception as e:
            print(f"❌ Erro ao ativar notificações: {e}")
            return

        # 🟢 Troca de chaves ECDH
        print("🔑 Iniciando troca de chaves...")
        private_key, public_key_bytes = generate_ecdh_keys()
        await client.write_gatt_char(CHAR_UUID_WRITE, CMD_KEY_EXCHANGE[:8] + public_key_bytes + bytes(8))

        # Aguarda a chave pública do dispositivo
        for _ in range(5):
            await asyncio.sleep(1)
            if terminal_public_key_bytes:
                print(f"📌 Chave pública recebida: {terminal_public_key_bytes.hex()}")
                break
        else:
            print("❌ Falha ao receber a chave pública do dispositivo.")
            return

        # 🟢 Derivar AES Key
        try:
            shared_secret = terminal_public_key_bytes + bytes(2)  # Simulando derivação
            aes_key = BASE_AES_KEY[:-6] + shared_secret
            print(f"🔐 AES Key derivada: {aes_key.hex()}")
        except Exception as e:
            print(f"❌ Erro ao derivar AES Key: {e}")
            return

        # 🟢 Enviar IMEI para autenticação
        print("📡 Enviando IMEI...")
        encrypted_imei = AES.new(aes_key, AES.MODE_ECB).encrypt(pad(CMD_SEND_IMEI[4:], AES.block_size))
        await client.write_gatt_char(CHAR_UUID_WRITE, CMD_SEND_IMEI[:4] + encrypted_imei)

        # 🟢 Aguarda resposta
        print("⌛ Aguardando resposta por 10 segundos...")
        await asyncio.sleep(10)

        # 🟢 Desconectar
        await client.stop_notify(CHAR_UUID_NOTIFY)
        print("🔌 Desconectando...")

    print("✅ Desconectado com sucesso.")


# 📌 Executar o script
asyncio.run(get_device_info())
