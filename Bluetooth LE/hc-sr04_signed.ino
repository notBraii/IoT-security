#include <Arduino.h>
#include "BLEDevice.h"
#include "BLEServer.h"
#include "BLEUtils.h"
#include "BLE2902.h"
#include "mbedtls/md.h"

// UUIDs compartidos con la Raspberry
#define SERVICE_UUID    "12345678-1234-5678-1234-56789abcdef0"
#define DATA_CHAR_UUID  "12345678-1234-5678-1234-56789abcdef2"

// MASTER KEY compartida (32 bytes = 256 bits)
// OJO: esta semilla debe ser la MISMA en la Raspberry (en hex)
const uint8_t MASTER_KEY[32] = {
  0x96, 0x79, 0x1c, 0x1d, 0xd4, 0x67, 0x94, 0x22,
  0x7f, 0x56, 0x2d, 0x02, 0xb7, 0x0a, 0x56, 0x67,
  0x65, 0xbf, 0xf0, 0x42, 0x7a, 0x17, 0xd5, 0x5a,
  0x3e, 0x0f, 0x5a, 0xf8, 0x30, 0x9c, 0x83, 0xf0
};

BLECharacteristic *pDataChar = nullptr;
uint32_t ctr = 0;  // contador de rotación

// --------------------------------------------------
// Función HMAC-SHA256 usando mbedtls
// --------------------------------------------------
void hmac_sha256(const uint8_t* key, size_t keylen,
                 const uint8_t* data, size_t datalen,
                 uint8_t out[32]) {
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, md_info, 1);

  mbedtls_md_hmac_starts(&ctx, key, keylen);
  mbedtls_md_hmac_update(&ctx, data, datalen);
  mbedtls_md_hmac_finish(&ctx, out);

  mbedtls_md_free(&ctx);
}

// Deriva K_ctr = HMAC(MASTER_KEY, ctr_bytes)
void derive_session_key(uint32_t counter, uint8_t out_key[32]) {
  uint8_t ctr_bytes[4];
  ctr_bytes[0] = (counter >> 24) & 0xFF;
  ctr_bytes[1] = (counter >> 16) & 0xFF;
  ctr_bytes[2] = (counter >> 8) & 0xFF;
  ctr_bytes[3] = (counter) & 0xFF;

  hmac_sha256(MASTER_KEY, sizeof(MASTER_KEY), ctr_bytes, sizeof(ctr_bytes), out_key);
}

// Convierte bytes a string hex para mandarla como texto
String toHex(const uint8_t* buf, size_t len) {
  String s;
  for (size_t i = 0; i < len; i++) {
    char tmp[3];
    sprintf(tmp, "%02x", buf[i]);
    s += tmp;
  }
  return s;
}

/*
 // Sensor de ultrasonido
*/

const int trigPin = 5;
const int echoPin = 18;

//Define velocidad de sonido en cm/uS
#define SOUND_SPEED 0.034

long duration;
float distanceCm;


void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println("ESP32: Configuración de pines trigger y echo");

  pinMode(trigPin, OUTPUT); // Sets the trigPin as an Output
  pinMode(echoPin, INPUT); // Sets the echoPin as an Input


  Serial.println("ESP32: inicio nodo de claves con seed compartida");

  // Inicializar BLE
  BLEDevice::init("Esp32KeyNode");
  BLEServer *pServer = BLEDevice::createServer();

  // Servicio GATT
  BLEService *pService = pServer->createService(SERVICE_UUID);

  // Characteristic para mensajes firmados (notify + read)
  pDataChar = pService->createCharacteristic(
    DATA_CHAR_UUID,
    BLECharacteristic::PROPERTY_NOTIFY | BLECharacteristic::PROPERTY_READ
  );

  // Descriptor para permitir notificaciones
  BLE2902 *p2902 = new BLE2902();
  p2902->setNotifications(true);
  pDataChar->addDescriptor(p2902);

  pService->start();

  // Advertising
  BLEAdvertising *pAdvertising = BLEDevice::getAdvertising();
  pAdvertising->addServiceUUID(SERVICE_UUID);
  pAdvertising->setScanResponse(true);
  pAdvertising->start();

  Serial.println("ESP32: BLE advertising iniciado");
}

void loop() {
  // Cada 5 segundos mandamos un mensaje "firmado"
  delay(5000);

  ctr++;  // rotamos clave aumentando contador

  // 1) Derivar clave de sesión
  uint8_t session_key[32];
  derive_session_key(ctr, session_key);

  // 2) Loop del sensor de ultrasonido
  
  // Clears the trigPin
  digitalWrite(trigPin, LOW);
  delayMicroseconds(2);
  // Sets the trigPin on HIGH state for 10 micro seconds
  digitalWrite(trigPin, HIGH);
  delayMicroseconds(10);
  digitalWrite(trigPin, LOW);
  
  // Reads the echoPin, returns the sound wave travel time in microseconds
  duration = pulseIn(echoPin, HIGH);
  
  // Calculate the distance
  distanceCm = duration * SOUND_SPEED/2;
  
  // Prints the distance in the Serial Monitor
  Serial.print("Distance (cm): ");
  Serial.println(distanceCm);
  
  String payload = "inicio...";
  if (distanceCm > 20){
    payload = "Libre";
  }
  else{
    payload = "Ocupado";
  };
  
  Serial.println(payload);

  // 3) HMAC sobre el payload
  uint8_t sig[32];
  hmac_sha256(session_key,
              sizeof(session_key),
              (const uint8_t*)payload.c_str(),
              payload.length(),
              sig);

  String sigHex = toHex(sig, 32);

  // 4) Construimos un JSON simple
  //    {"ctr":123,"payload":"...","sig":"..."}
  String json = "{";
  json += "\"ctr\":";
  json += String(ctr);
  json += ",\"payload\":\"";
  json += payload;
  json += "\",\"sig\":\"";
  json += sigHex;
  json += "\"}";

  Serial.print("ESP32: enviando -> ");
  Serial.println(json);

  // 5) Lo mandamos por la characteristic (notify)
  if (pDataChar) {
    pDataChar->setValue(json.c_str());
    pDataChar->notify();
  }
}
