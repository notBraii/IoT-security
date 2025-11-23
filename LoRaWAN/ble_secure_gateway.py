#!/usr/bin/env python3
import asyncio
import json
import hmac
import hashlib
from bleak import BleakScanner, BleakClient

# Misma master key que en el ESP32 (hex -> bytes)
MASTER_KEY_HEX = "96791c1dd46794227f562d02b70a566765bff0427a17d55a3e0f5af8309c83f0"
MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)

SERVICE_UUID   = "12345678-1234-5678-1234-56789abcdef0".lower()
DATA_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef2"

ESP32_NAME = "Esp32KeyNode"   # el nombre que pusimos en BLEDevice::init()

# Guardamos último ctr visto por dispositivo para evitar replays (opcional)
last_ctr = {}


def derive_session_key(ctr: int) -> bytes:
    """K_ctr = HMAC_SHA256(MASTER_KEY, ctr_bytes)"""
    ctr_bytes = ctr.to_bytes(4, byteorder="big", signed=False)
    return hmac.new(MASTER_KEY, ctr_bytes, hashlib.sha256).digest()


def handle_notification(address: str):
    """Devuelve una función callback para manejar notificaciones de ese dispositivo."""

    def callback(sender, data: bytes):
        try:
            s = data.decode("utf-8")
            print(f"[{address}] Notificación raw:", s)

            obj = json.loads(s)
            ctr = int(obj["ctr"])
            payload = obj["payload"]
            sig_hex = obj["sig"]

            # Anti-replay sencillo (opcional)
            prev = last_ctr.get(address, -1)
            if ctr <= prev:
                print(f"[{address}] ALERTA: ctr={ctr} <= last_ctr={prev} (posible replay)")
                return

            # Derivar clave de sesión
            K_ctr = derive_session_key(ctr)

            # Recalcular HMAC del payload
            expected_sig = hmac.new(
                K_ctr, payload.encode("utf-8"), hashlib.sha256
            ).hexdigest()

            if hmac.compare_digest(expected_sig, sig_hex):
                print(f"[{address}] OK firma válida - ctr={ctr}, payload='{payload}'")
                last_ctr[address] = ctr
            else:
                print(f"[{address}] ERROR firma inválida")
                print(f"  esperada={expected_sig}")
                print(f"  recibida={sig_hex}")

        except Exception as e:
            print(f"[{address}] ERROR procesando notificación:", e)

    return callback


async def find_device():
    """
    Busca el ESP32 de dos formas:
    - por nombre BLE (ESP32_NAME)
    - y si existe .details o .metadata, imprime info extra
    """
    print("Escaneando dispositivos BLE...")
    devices = await BleakScanner.discover(timeout=5.0)

    for d in devices:
        print("Encontrado:", d.address, d.name)

    # Primero intentamos por nombre
    for d in devices:
        if d.name == ESP32_NAME:
            print(">> Usando dispositivo encontrado por nombre:")
            print("   Address:", d.address)
            print("   Name   :", d.name)
            return d

    # Si quisieras intentar por UUID anunciado, pero tu versión no tiene metadata,
    # puedes simplemente quedarte con el primero que se llame parecido.
    print(f"No se encontró ningún dispositivo con nombre '{ESP32_NAME}'.")
    return None


async def main():
    dev = await find_device()
    if dev is None:
        print("No se encontró ESP32, revisa que esté encendido y anunciando.")
        return

    address = dev.address

    print(f"Conectando a {address}...")
    async with BleakClient(address) as client:
        print("Conectado.")

        # Nos suscribimos a notificaciones de la characteristic de datos
        await client.start_notify(DATA_CHAR_UUID, handle_notification(address))
        print("Escuchando notificaciones (Ctrl+C para salir)...")

        try:
            while True:
                await asyncio.sleep(1.0)
        except KeyboardInterrupt:
            print("Saliendo...")


if __name__ == "__main__":
    asyncio.run(main())
