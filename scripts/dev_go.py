import asyncio, socket, time, traceback

s = socket.socket(); s.settimeout(6); t0 = time.time()
try:
    s.connect(("127.0.0.1", 27015)); ok = True; info = f"{time.time()-t0:.2f}s"
except Exception as e:
    ok = False; info = repr(e)
finally:
    s.close()
print(f"[1] tcp 127.0.0.1:27015 -> {ok} ({info})")
if not ok:
    raise SystemExit(1)

from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.lockdown import create_using_usbmux

async def main():
    devs = await list_devices()
    print(f"[2] devices = {len(devs)}")
    for d in devs:
        print(f"    serial={d.serial} conn={getattr(d,'connection_type',None)}")
    if not devs:
        return
    ser = devs[0].serial
    try:
        async with create_using_usbmux(serial=ser) as ld:
            v = ld.all_values
    except Exception:
        traceback.print_exc()
        ld = await create_using_usbmux(serial=ser)
        v = ld.all_values
    print("[3] lockdown:")
    for k in ("DeviceName","ProductType","ProductVersion","BuildVersion","UniqueDeviceID",
              "CPUArchitecture","HardwareModel","SerialNumber","PasswordProtected"):
        if k in v: print(f"    {k} = {v[k]}")

asyncio.run(main())
