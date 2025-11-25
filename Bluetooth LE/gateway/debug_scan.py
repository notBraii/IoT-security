import asyncio
from bleak import BleakScanner

# Tu MAC Address específica
TARGET_MAC = "7C:9E:BD:37:2A:52"

def detection_callback(device, advertisement_data):
    # Filtramos para ver SOLO tu ESP32 y evitar ruido
    if device.address.upper() == TARGET_MAC:
        print(f"\n--- TU ESP32 ENCONTRADO ---")
        print(f"MAC: {device.address}")
        
        # --- CORRECCIÓN PARA BLEAK 2.0.0 ---
        # El RSSI ahora está en advertisement_data, no en device
        try:
            print(f"RSSI: {advertisement_data.rssi}")
        except:
            print("RSSI: No disponible")
        
        # --- INSPECCIÓN DE DATOS ---
        raw_data = advertisement_data.manufacturer_data
        print(f"Diccionario de Fabricante (RAW): {raw_data}")
        
        # Verificamos si la llave 0xFFFF (65535) existe
        if 0xFFFF in raw_data:
            # Convertimos a hex para que puedas leerlo
            payload_hex = raw_data[0xFFFF].hex()
            print(f"✅ PAYLOAD DETECTADO: {payload_hex}")
            print(f"   Longitud: {len(raw_data[0xFFFF])} bytes")
        else:
            print("⚠️ AVISO: El diccionario está vacío o tiene otra ID.")
            # Si hay otras llaves, las mostramos
            for k, v in raw_data.items():
                print(f"   Llave encontrada: {k} -> {v.hex()}")

async def main():
    print(f"Escaneando buscando {TARGET_MAC} con Bleak {2.0}...")
    
    # Callback continuo
    scanner = BleakScanner(detection_callback=detection_callback)
    
    await scanner.start()
    # Escaneamos por 10 segundos
    await asyncio.sleep(10) 
    await scanner.stop()
    print("Escaneo finalizado.")

if __name__ == "__main__":
    asyncio.run(main())