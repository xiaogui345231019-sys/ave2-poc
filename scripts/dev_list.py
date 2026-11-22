import asyncio, traceback
from pymobiledevice3.usbmux import list_devices

async def main():
    devs = await list_devices()
    print(f"=== devices: {len(devs)} ===")
    for d in devs:
        print("  ", {k: d.__dict__.get(k) for k in ("serial","connection_type","product_id","device_id") if k in d.__dict__})
    return devs

asyncio.run(main())
