import socket, threading, time
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    srv.bind(("127.0.0.1", 27015)); srv.listen(5)
    print("  bind+listen: OK")
except Exception as e:
    print("  bind failed:", e); raise SystemExit(1)
def acc():
    try:
        c, a = srv.accept(); print("  accept: OK from", a); c.close()
    except Exception as e:
        print("  accept err:", e)
t = threading.Thread(target=acc, daemon=True); t.start()
time.sleep(0.3)
c = socket.socket(); c.settimeout(5); t0 = time.time()
try:
    c.connect(("127.0.0.1", 27015)); print(f"  self-connect: OK in {time.time()-t0:.3f}s")
except Exception as e:
    print(f"  self-connect FAILED after {time.time()-t0:.2f}s: {e}")
finally:
    c.close()
time.sleep(0.5); srv.close()
