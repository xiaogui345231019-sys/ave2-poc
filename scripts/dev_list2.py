import asyncio, traceback
from pymobiledevice3.usbmux import list_devices

ADDR = ("127.0.0.2", 27015)

async def main():
    try:
        devs = await list_devices(usbmux_address=ADDR)
    except Exception:
        print("=== list_devices FAILED ==="); traceback.print_exc(); return
    print(f"=== devices via {ADDR}: {len(devs)} ===")
    for d in devs:
        p = getattr(d, "properties", None) or d.__dict__.get("Properties") or {}
        print("  serial:", d.serial, "| conn:", getattr(d,'connection_type',None))
        for k in ("DeviceName","ProductType","ProductVersion","BuildVersion","DeviceClass"):
            if k in p: print(f"    {k} = {p[k]}")

asyncio.run(main())
