import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(20)
t0 = time.time()
try:
    s.connect(("127.0.0.1", 27015))
    print(f"connected in {time.time()-t0:.2f}s")
except Exception as e:
    print(f"failed after {time.time()-t0:.2f}s: {e}")
