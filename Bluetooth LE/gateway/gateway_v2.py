import asyncio
import struct
import hmac
import hashlib
import binascii
from bleak import BleakScanner

# --- CONFIGURACIÓN ---

# MASTER KEY: Debe ser EXACTAMENTE la misma que en el ESP32
MASTER_KEY = bytes([
    0x96, 0x79, 0x1c, 0x1d, 0xd4, 0x67, 0x94, 0x22,
    0x7f, 0x56, 0x2d, 0x02, 0xb7, 0x0a, 0x56, 0x67,
    0x65, 0xbf, 0xf0, 0x42, 0x7a, 0x17, 0xd5, 0x5a,
    0x3e, 0x0f, 0x5a, 0xf8, 0x30, 0x9c, 0x83, 0xf0
])

# ID de Fabricante (0xFFFF es testing)
TARGET_MANUFACTURER_ID = 0xFFFF

def derive_session_key(counter_val):
    """
    Deriva la clave de sesión usando HMAC-SHA256(MASTER_KEY, counter).
    El counter entra como 4 bytes Big-Endian.
    """
    ctr_bytes = struct.pack(">I", counter_val)
    k_sess = hmac.new(MASTER_KEY, ctr_bytes, hashlib.sha256).digest()
    return k_sess

def process_packet(device, advertising_data):
    """
    Callback que se ejecuta cada vez que se detecta un paquete BLE.
    """
    # Primer filtro: Se verifica que sea un dispositivo del ecosistema
    if TARGET_MANUFACTURER_ID not in advertising_data.manufacturer_data:
        return

    # Se extrae el payload asociado al ID
    payload = advertising_data.manufacturer_data[TARGET_MANUFACTURER_ID]
    
    # Verificación de longitud mínima (11 bytes: 4 CTR + 1 ENC + 6 SIG)
    if len(payload) != 11: 
        return

    # Se obtiene el RSSI (Indicador de Potencia de la señal recibida en dBm)
    rssi_val = advertising_data.rssi

    # --- 1. DESEMPAQUETADO ---
    ctr_bytes = payload[0:4]
    encrypted_byte = payload[4]
    received_sig = payload[5:]

    # Convertir bytes a entero
    counter_val = struct.unpack(">I", ctr_bytes)[0]

    # --- 2. CRIPTOGRAFÍA ---
    
    # A) Derivar clave de sesión
    session_key = derive_session_key(counter_val)

    # B) Verificar Firma (Autenticidad)
    data_to_sign = ctr_bytes + bytes([encrypted_byte])
    full_signature = hmac.new(session_key, data_to_sign, hashlib.sha256).digest()
    expected_sig = full_signature[:6] 

    is_valid_signature = hmac.compare_digest(received_sig, expected_sig)

    # C) Desencriptar (Confidencialidad)
    decrypted_val = encrypted_byte ^ session_key[0]
    
    # Interpretación
    status_str = "LIBRE" if decrypted_val == 1 else "OCUPADO"
    if decrypted_val not in [0, 1]: 
        status_str = f"DESCONOCIDO ({decrypted_val})"

    # --- 3. IMPRESIÓN (Solo si la firma es válida para no llenar log de basura) ---
    if is_valid_signature:
        print("-" * 60)
        # Usamos la MAC para identificar CUÁL sensor es
        print(f" Sensor Detectado: {device.address} | RSSI: {rssi_val}dBm")
        print(f" Payload (Hex): {binascii.hexlify(payload).decode()}")
        print(f" Contador: {counter_val}")
        print(f" Estado: {status_str}")
        print("-" * 60)
    else:
        # Opcional: Imprimir intentos fallidos (ataques o errores)
        print(f" OJO!! Firma inválida de {device.address} (CTR: {counter_val})")

async def main():
    print("Iniciando escáner seguro BLE (Modo Activo)...")
    print(f"Filtrando por ID de fabricante: {hex(TARGET_MANUFACTURER_ID)}")
    
    # Forzado del adaptador a despertar y pedir datos activamente
    scanner = BleakScanner(
        detection_callback=process_packet,
        scanning_mode="active" 
    )
    
    await scanner.start()

    try:
        # Bucle infinito eficiente
        while True:
            await asyncio.sleep(1)
            
    except asyncio.CancelledError:
        print("\nTarea cancelada.")
    except KeyboardInterrupt:
        print("\nUsuario solicitó detener.")
    finally:
        print("Deteniendo escáner Bluetooth...")
        await scanner.stop()
        print("Escáner detenido.")

if __name__ == "__main__":
    asyncio.run(main())