import asyncio
import hmac
import hashlib
import struct
from bleak import BleakScanner

# --- 1. CONFIGURACIÓN DE SEGURIDAD ---
# ESTA CLAVE DEBE SER IDÉNTICA A LA DEL ESP32
# Copiada del código Arduino Nivel 2
MASTER_KEY = bytes([
  0x96, 0x79, 0x1c, 0x1d, 0xd4, 0x67, 0x94, 0x22,
  0x7f, 0x56, 0x2d, 0x02, 0xb7, 0x0a, 0x56, 0x67,
  0x65, 0xbf, 0xf0, 0x42, 0x7a, 0x17, 0xd5, 0x5a,
  0x3e, 0x0f, 0x5a, 0xf8, 0x30, 0x9c, 0x83, 0xf0
])

# Memoria volátil para guardar el último contador visto de cada dispositivo
# Estructura: { 'AA:BB:CC:DD:EE:FF': ultimo_ctr }
device_registry = {}

def derive_session_key(ctr_int):
    """Genera la misma clave efímera que hizo el ESP32 para este contador."""
    # Convertir el entero CTR a 4 bytes (Big Endian)
    ctr_bytes = ctr_int.to_bytes(4, byteorder='big')
    # HMAC-SHA256
    return hmac.new(MASTER_KEY, ctr_bytes, hashlib.sha256).digest()

def parse_parking_data(device, advertising_data):
    """Analiza el paquete y valida la criptografía."""
    
    # El diccionario manufacturer_data usa el ID (int) como clave.
    # En Arduino pusimos 0xFFFF como ID manual en el payload, pero Bleak 
    # a veces agrupa por el ID real del paquete. 
    # Buscamos la clave 65535 (0xFFFF).
    if 0xFFFF not in advertising_data.manufacturer_data:
        return

    # Obtenemos los bytes crudos (sin los 2 bytes del ID que Bleak ya procesó como Key)
    # NOTA: Dependiendo de cómo BLEDevice (Arduino) construyó el paquete, 
    # a veces los bytes raw incluyen el ID manual que pusimos.
    # Asumimos que Bleak nos da el array de bytes asociado al ID.
    raw_bytes = advertising_data.manufacturer_data[0xFFFF]
    
    # El código Arduino envía: [ID(2)] [CTR(4)] [Dato(1)] [Firma(6)] = 13 bytes en total en el array.
    # Bleak suele entregar el valor. Si Arduino puso el ID dentro del array de datos:
    # Verificamos longitud.
    
    # Ajuste según comportamiento típico de ESP32 BLE Lib:
    # Si enviaste payload completo "FF FF ...", Bleak puede ver el ID 0xFFFF y el payload restante,
    # O entregarte todo. Vamos a ser defensivos.
    
    payload = raw_bytes
    
    # Si el array empieza con FF FF (nuestro ID manual), lo cortamos
    if len(payload) >= 2 and payload[0] == 0xFF and payload[1] == 0xFF:
        payload = payload[2:] # Quitamos el ID manual para procesar
    
    # Ahora esperamos: [CTR(4)] + [EncStatus(1)] + [Firma(6)] = 11 bytes
    if len(payload) != 11:
        # print(f"Paquete con longitud incorrecta: {len(payload)}")
        return

    # --- DESEMPAQUETAR ---
    # >I = Big Endian Unsigned Int (4 bytes)
    # B = Unsigned Char (1 byte)
    # 6s = 6 bytes string
    ctr_received, enc_status_byte, signature_received = struct.unpack('>IB6s', payload)

    mac_address = device.address

    # --- 1. VALIDACIÓN ANTI-REPLAY (Básica) ---
    if mac_address in device_registry:
        if ctr_received <= device_registry[mac_address]:
            print(f"[ATAQUE] Replay detectado o paquete viejo de {mac_address}. CTR {ctr_received} <= {device_registry[mac_address]}")
            return
    
    # --- 2. VALIDACIÓN DE FIRMA (Autenticidad) ---
    # Recalculamos la Session Key localmente
    session_key = derive_session_key(ctr_received)
    
    # Reconstruimos lo que se firmó: [CTR] + [EncData]
    data_to_verify = struct.pack('>IB', ctr_received, enc_status_byte)
    
    # Calculamos HMAC local
    calculated_hmac = hmac.new(session_key, data_to_verify, hashlib.sha256).digest()
    calculated_signature = calculated_hmac[:6] # Truncamos a 6 bytes
    
    if calculated_signature != signature_received:
        print(f"[ALERTA] Firma inválida de {mac_address}. Posible falsificación.")
        return

    # --- 3. DESCIFRADO (Confidencialidad) ---
    # Si llegamos aquí, el paquete es AUTÉNTICO y VIENE DEL DUEÑO DE LA CLAVE.
    
    # XOR para recuperar el dato original
    # Python bytes son enteros al iterar
    decrypted_status = enc_status_byte ^ session_key[0]
    
    # Actualizar registro
    device_registry[mac_address] = ctr_received
    
    # --- RESULTADO FINAL ---
    estado_txt = "LIBRE 🟢" if decrypted_status == 1 else "OCUPADO 🔴"
    
    print(f"✅ [{mac_address}] CTR:{ctr_received} -> Estado: {estado_txt}")


async def main():
    print("Iniciando Gateway de Estacionamiento Seguro...")
    print("Escuchando paquetes cifrados (ID 0xFFFF)...")
    
    # Usamos un callback para detección continua
    scanner = BleakScanner(detection_callback=parse_parking_data)
    
    await scanner.start()
    
    # Mantener el script corriendo indefinidamente
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    asyncio.run(main())