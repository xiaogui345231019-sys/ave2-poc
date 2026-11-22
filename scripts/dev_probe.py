import sys, json, traceback
try:
    from pymobiledevice3.lockdown import create_using_usbmux
    with create_using_usbmux() as ld:
        v = ld.all_values
        keys = ("DeviceName","ProductType","ProductVersion","BuildVersion","UniqueDeviceID","CPUArchitecture","HardwareModel","SerialNumber","PasswordProtected","DeveloperModeStatus")
        print("=== lockdown ok ===")
        for k in keys:
            if k in v: print(f"  {k} = {v[k]}")
        print(f"  (all_values keys: {len(v)})")
except Exception:
    print("=== lockdown FAILED ===")
    traceback.print_exc()
