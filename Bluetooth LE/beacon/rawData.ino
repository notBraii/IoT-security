 #include <Arduino.h>

#include "BLEDevice.h"

#include "BLEUtils.h"

#include "BLEServer.h"


// Pines del Ultrasonido

const int trigPin = 5;

const int echoPin = 18;


BLEAdvertising *pAdvertising;


void setup() {

Serial.begin(115200);

pinMode(trigPin, OUTPUT);

pinMode(echoPin, INPUT);


// 1. Inicializar Hardware BLE

BLEDevice::init("Parking-Sensor-01");

pAdvertising = BLEDevice::getAdvertising();

Serial.println("Nivel 1: Iniciado. Enviando datos en texto plano...");

}


void loop() {

// --- A. Leer Distancia (Simulado o Real) ---

long duration;

digitalWrite(trigPin, LOW); delayMicroseconds(2);

digitalWrite(trigPin, HIGH); delayMicroseconds(10);

digitalWrite(trigPin, LOW);

duration = pulseIn(echoPin, HIGH);

float distanceCm = duration * 0.034 / 2;


// Lógica simple de estado

// 1 = Libre, 0 = Ocupado

uint8_t estado = (distanceCm > 20) ? 1 : 0;


Serial.printf("Dist: %.1f cm -> Estado: %d\n", distanceCm, estado);


// --- B. Construir el Paquete BLE (Advertising) ---

// Vamos a poner el dato crudo en el "Manufacturer Data"

std::string payload = "";

// Identificador de fabricante falso (0xFFFF es reservado para test)

payload += (char)0xFF;

payload += (char)0xFF;

// AÑADIMOS EL DATO SIN PROTECCIÓN

// Literalmente enviamos "L" (Libre) o "O" (Ocupado) para que se lea fácil

if(estado == 1) payload += "LIBRE";

else payload += "OCUPADO";


// --- C. Configurar y Enviar ---

BLEAdvertisementData oAdvertisementData = BLEAdvertisementData();

oAdvertisementData.setFlags(0x04); // BR_EDR_NOT_SUPPORTED

oAdvertisementData.setManufacturerData(payload.c_str());


pAdvertising->setAdvertisementData(oAdvertisementData);

pAdvertising->start();


// Mantenemos el anuncio 1 segundo y luego paramos para simular ahorro

delay(1000);

pAdvertising->stop();

// Esperar 2 segundos antes de la siguiente medición

delay(2000);

} 