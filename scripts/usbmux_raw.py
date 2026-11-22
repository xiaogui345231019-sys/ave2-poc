import socket, struct, plistlib
try:
    s = socket.create_connection(("127.0.0.1", 27015), timeout=5)
    print("  connect: OK")
    body = plistlib.dumps({}).decode()
    payload = body.encode()
    hdr = struct.pack("<IIII", 16 + len(payload), 1, 8, 1)   # ListDevices
    s.sendall(hdr + payload)
    raw = s.recv(4)
    if len(raw) < 4:
        print("  short read"); raise SystemExit
    ln = struct.unpack("<I", raw)[0]
    buf = b""
    while len(buf) < ln - 4:
        c = s.recv(ln - 4 - len(buf))
        if not c: break
        buf += c
    print("  resp len:", ln)
    d = plistlib.loads(buf[4:])   # skip version/message/tag
    devs = d.get("DeviceList", [])
    print("  devices:", len(devs))
    for x in devs:
        p = x.get("Properties", {})
        print("   ", p.get("DeviceName"), p.get("ProductType"), p.get("ProductVersion"), p.get("SerialNumber"))
except Exception as e:
    import traceback; traceback.print_exc()
