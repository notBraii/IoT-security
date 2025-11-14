from bleak import BleakScanner
import asyncio

def on_detect(device, adv):
    # Filtrar solo si tiene service_data y contiene el UUID '0000feaa'
    if not adv.service_data:
        return

    for uuid, data in adv.service_data.items():
        if uuid.lower().startswith("0000feaa"):
            nombre = device.name if device.name else "(sin nombre)"
            hex_data = " ".join(f"{b:02X}" for b in data)
            print(f"📡 Beacon Eddystone detectado:")
            print(f"  Nombre: {nombre}")
            print(f"  Dirección: {device.address}")
            print(f"  RSSI: {adv.rssi} dBm")
            print(f"  Service UUID: {uuid}")
            print(f"  Datos: {hex_data}")
            print("-" * 60)

async def main():
    scanner = BleakScanner(detection_callback=on_detect)
    await scanner.start()
    print("🔍 Escuchando beacons con UUID 0000FEAA... (Ctrl+C para salir)")
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        await scanner.stop()

if __name__ == "__main__":
    asyncio.run(main())