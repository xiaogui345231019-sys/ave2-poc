import socket, time
for port in (27016, 27015):
    s = socket.socket(); s.settimeout(8); t0=time.time()
    try:
        s.connect(("127.0.0.1", port)); print(f"  {port}: connected in {time.time()-t0:.2f}s")
    except Exception as e:
        print(f"  {port}: failed after {time.time()-t0:.2f}s: {e}")
    finally: s.close()
