import socket, time, asyncio, traceback

# 1) connectivity
s = socket.socket(); s.settimeout(6); t0 = time.time()
try:
    s.connect(("127.0.0.1", 27015))
    print(f"[1] 127.0.0.1:27015 connected in {time.time()-t0:.2f}s")
except Exception as e:
    print(f"[1] 127.0.0.1:27015 FAILED after {time.time()-t0:.2f}s: {e}")
    raise SystemExit(1)
finally:
    s.close()

# 2) list devices
from pymobiledevice3.usbmux import list_devices
async def main():
    devs = await list_devices()
    print(f"[2] devices: {len(devs)}")
    for d in devs:
        p = getattr(d, "properties", None) or {}
        print(f"    serial={d.serial} conn={getattr(d,'connection_type',None)}")
        for k in ("DeviceName","ProductType","ProductVersion","BuildVersion","DeviceClass","UniqueDeviceID"):
            if k in p: print(f"      {k} = {p[k]}")
asyncio.run(main())
