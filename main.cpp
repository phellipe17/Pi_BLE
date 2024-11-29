#include <tinyb.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random> 
#include <cstdint>

#define DEVICE_ADDRES "CB:59:2E:9F:76:11"
#define WRITE_CHARACTERISTIC_UUID "00007000-0000-1000-8000-00805f9b34fb"
#define NOTIFY_CHARACTERISTIC_UUID "a0340004-b5a3-f393-e0a9-e50e24dcca9e"

using namespace std;
using namespace tinyb;



// Sobrecarga do operador + para std::vector<uint8_t>
std::vector<uint8_t> operator+(const std::vector<uint8_t>& v1, const std::vector<uint8_t>& v2) {
    std::vector<uint8_t> result = v1;
    result.insert(result.end(), v2.begin(), v2.end());
    return result;
}

std::pair<int, std::vector<uint8_t>> generateEcdhKeys() {
    // Gerador de números aleatórios
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, std::numeric_limits<int16_t>::max());

    // Gera uma chave privada como um número inteiro de 2 bytes
    int privateKey = dis(gen);

    // Constante g
    int g = 0x83A5;

    // Calcula a chave pública
    int publicKey = privateKey * g;

    // Converte a chave pública para um vetor de bytes (4 bytes para int)
    vector<uint8_t> publicKeyBytes(4);
    publicKeyBytes[0] = (publicKey >> 24) & 0xFF; // Byte mais significativo
    publicKeyBytes[1] = (publicKey >> 16) & 0xFF;
    publicKeyBytes[2] = (publicKey >> 8) & 0xFF;
    publicKeyBytes[3] = publicKey & 0xFF;        // Byte menos significativo

    // Retorna a chave privada e a chave pública em formato de bytes
    return {privateKey, publicKeyBytes};
}

// Função callback chamada quando uma notificação é recebida
void notification_callback(vector<unsigned char> &value) {
    ostringstream hexStream;
    for (unsigned char c : value) {
        hexStream << hex << setw(2) << setfill('0') << (int)c;
    }
    cout << "Notificação recebida! Novo valor: " << hexStream.str() << endl;
}

int main() {
    try {
        // Obter o gerenciador de Bluetooth
        auto manager = tinyb::BluetoothManager::get_bluetooth_manager();
        auto adapter = manager->get_adapters().at(0).get();

        // Iniciar o escaneamento de dispositivos BLE
        cout << "Escaneando dispositivos BLE..." << endl;
        adapter->start_discovery();

        // Espera até encontrar pelo menos um dispositivo
        if(adapter == nullptr) {
            cout << "Nenhum adaptador encontrado." << endl;
            return 1;
        }

        // auto devices = manager->get_devices();
        auto devices = manager->get_devices();
        unique_ptr<tinyb::BluetoothDevice> device = nullptr;
        while (device == nullptr) {
            devices = manager->get_devices();
            for (auto &d : devices) {
                if (d->get_address() == DEVICE_ADDRES) {
                    device = move(d);
                    cout << "Dispositivo encontrado " << endl;
                    break;
                }
            }
            this_thread::sleep_for(chrono::seconds(1));
        }

        // Exibe os dispositivos encontrados
        // for (auto &device : devices) {
        //     cout << "Encontrado: " << device->get_name() << " - " << device->get_address() << endl;
        // }

        // Conectar-se ao primeiro dispositivo encontrado
        while(true){
            try {
                device->connect();
                break;
            } catch (const exception &e) {
                cout << "Erro: " << e.what() << endl;
                this_thread::sleep_for(chrono::seconds(1));
            }
        }
        // device->connect();
        cout << "Conectado ao dispositivo " << device->get_name() << endl;

        // Obter o serviço GATT do dispositivo
        auto services = device->get_services();
        

        // Procurar por uma característica que tenha a propriedade de notificação

        BluetoothGattCharacteristic *write_characteristic = nullptr;
        BluetoothGattCharacteristic *notify_characteristic = nullptr;

        for (auto &service : services) {
            auto characteristics = service->get_characteristics();
            for (auto &ch : characteristics) {
                // Verificar se a característica tem a propriedade NOTIFY
                auto uuid = ch->get_uuid();
                if(uuid == WRITE_CHARACTERISTIC_UUID) {
                    cout << "Característica de escrita encontrada!" << endl;
                    
                    write_characteristic = ch.get();
                } else if(uuid == NOTIFY_CHARACTERISTIC_UUID) {
                    cout << "Característica de notificação encontrada!" << endl;

                    notify_characteristic = ch.get();
                }
            }
        }

        if (notify_characteristic != nullptr) {
            // Habilitar a notificação
            notify_characteristic->enable_value_notifications(notification_callback);
            cout << "Notificações habilitadas para a característica!" << endl;

            // Enquanto o programa estiver rodando, ele vai receber notificações
            while (true) {
                // Aqui, você pode adicionar lógica para manter o programa ativo e receber notificações
                // Simulando um processo contínuo, sem fazer nada por enquanto
                this_thread::sleep_for(chrono::seconds(1));
            }
        } else {
            cout << "Nenhuma característica de notificação encontrada." << endl;
        }

        auto keys = generateEcdhKeys();

        auto privateKey = keys.first;

        auto publicKey = keys.second;

        vector<uint8_t> messageKeyExchange = {0x42, 0x54, 0x11, 0x01, 0x89, 0x00,0xc2, 0x00};

        vector<uint8_t> a = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};


        vector<uint8_t> combined = messageKeyExchange + publicKey + a;


        write_characteristic->write_value(publicKey);

        // // Desconectar do dispositivo
        // device.disconnect();
        // cout << "Desconectado do dispositivo." << endl;

    } catch (const exception &e) {
        cerr << "Erro: " << e.what() << endl;
    }

    return 0;
}




