#include <Arduino.h>
#include "BLEDevice.h"
#include "BLEUtils.h"
#include "BLEServer.h"
#include "mbedtls/md.h" // Motor criptográfico del ESP32

// --- CONFIGURACIÓN DE HARDWARE ---
const int trigPin = 5;
const int echoPin = 18;

// --- SECRETOS (MASTER KEY) ---
// Esta clave debe ser IGUAL en tu Gateway (Receptor)
// 32 bytes aleatorios (256 bits)
const uint8_t MASTER_KEY[32] = {
  0x96, 0x79, 0x1c, 0x1d, 0xd4, 0x67, 0x94, 0x22, 
  0x7f, 0x56, 0x2d, 0x02, 0xb7, 0x0a, 0x56, 0x67,
  0x65, 0xbf, 0xf0, 0x42, 0x7a, 0x17, 0xd5, 0x5a,
  0x3e, 0x0f, 0x5a, 0xf8, 0x30, 0x9c, 0x83, 0xf0
};

// Contador de seguridad (Anti-Replay)
// En Nivel 3 lo guardaremos en memoria permanente. Por ahora se resetea al apagar.
uint32_t ctr = 0; 

BLEAdvertising *pAdvertising;

// --- FUNCIONES DE AYUDA CRIPTOGRÁFICA ---

// Función genérica para calcular HMAC-SHA256
void hmac_sha256(const uint8_t* key, size_t keylen, const uint8_t* data, size_t datalen, uint8_t out[32]) {
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, md_info, 1);
  mbedtls_md_hmac_starts(&ctx, key, keylen);
  mbedtls_md_hmac_update(&ctx, data, datalen);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// Derivar una clave efímera para ESTE mensaje específico (basada en el contador)
void derive_session_key(uint32_t counter, uint8_t out_key[32]) {
  uint8_t ctr_bytes[4];
  // Convertir entero de 32 bits a 4 bytes (Big Endian)
  ctr_bytes[0] = (counter >> 24) & 0xFF;
  ctr_bytes[1] = (counter >> 16) & 0xFF;
  ctr_bytes[2] = (counter >> 8) & 0xFF;
  ctr_bytes[3] = (counter) & 0xFF;
  
  hmac_sha256(MASTER_KEY, sizeof(MASTER_KEY), ctr_bytes, sizeof(ctr_bytes), out_key);
}

void setup() {
  Serial.begin(115200);
  pinMode(trigPin, OUTPUT);
  pinMode(echoPin, INPUT);

  // Inicializamos BLE pero con un nombre VACÍO para ser más discretos
  BLEDevice::init(""); 
  pAdvertising = BLEDevice::getAdvertising();
  
  Serial.println("Nivel 2: Cifrado Activado.");
}

void loop() {
  // 1. LEER SENSOR
  digitalWrite(trigPin, LOW); delayMicroseconds(2);
  digitalWrite(trigPin, HIGH); delayMicroseconds(10);
  digitalWrite(trigPin, LOW);
  long duration = pulseIn(echoPin, HIGH, 25000); // Timeout 25ms
  float distanceCm = duration * 0.034 / 2;
  
  // Estado real: 1 (Libre), 0 (Ocupado)
  uint8_t real_status = (distanceCm > 20 && duration > 0) ? 0x01 : 0x00;

  // 2. PREPARAR SEGURIDAD
  ctr++; // IMPORTANTE: Subir contador SIEMPRE antes de enviar
  
  // Generar clave de sesión única para este momento
  uint8_t session_key[32];
  derive_session_key(ctr, session_key);

  // 3. CIFRAR EL DATO (Confidencialidad)
  // Usamos el primer byte de la clave de sesión como máscara XOR
  uint8_t encrypted_status = real_status ^ session_key[0];

  // 4. FIRMAR EL PAQUETE (Autenticidad)
  // Queremos firmar: [CTR (4 bytes)] + [DatoCifrado (1 byte)]
  uint8_t data_to_sign[5];
  data_to_sign[0] = (ctr >> 24) & 0xFF;
  data_to_sign[1] = (ctr >> 16) & 0xFF;
  data_to_sign[2] = (ctr >> 8) & 0xFF;
  data_to_sign[3] = (ctr) & 0xFF;
  data_to_sign[4] = encrypted_status;

  uint8_t signature[32];
  hmac_sha256(session_key, 32, data_to_sign, 5, signature);

  // 5. CONSTRUIR PAQUETE FINAL (Raw Bytes)
  // Estructura: [ID (2)] + [CTR (4)] + [EncData (1)] + [Firma (6)] = 13 bytes
  uint8_t payload[13];
  
  // ID Fabricante (Fake)
  payload[0] = 0xFF; 
  payload[1] = 0xFF;
  
  // Copiar CTR
  payload[2] = data_to_sign[0];
  payload[3] = data_to_sign[1];
  payload[4] = data_to_sign[2];
  payload[5] = data_to_sign[3];
  
  // Copiar Dato Cifrado
  payload[6] = encrypted_status;
  
  // Copiar Firma (Truncada a 6 bytes)
  for(int i=0; i<6; i++) {
    payload[7+i] = signature[i];
  }

  // Debug por Serial para que entiendas lo que pasa
  Serial.printf("CTR: %d | Real: %d | Cifrado: 0x%02X\n", ctr, real_status, encrypted_status);

  // 6. ENVIAR (Advertising)
  BLEAdvertisementData oAdvertisementData = BLEAdvertisementData();
  oAdvertisementData.setFlags(0x04);
  
  // Conversión eficiente para inyectar el array binario
  std::string strPayload((char*)payload, 13);
  oAdvertisementData.setManufacturerData(strPayload.c_str());

  pAdvertising->setAdvertisementData(oAdvertisementData);
  pAdvertising->start();
  delay(1000);
  pAdvertising->stop();
  
  delay(2000);
}