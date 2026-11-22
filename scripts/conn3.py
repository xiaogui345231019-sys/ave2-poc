import socket, time
for attempt in range(3):
    s = socket.socket(); s.settimeout(3); t0=time.time()
    try:
        s.connect(("127.0.0.1", 27015)); print(f"  attempt{attempt}: OK {time.time()-t0:.3f}s"); s.close(); break
    except Exception as e:
        print(f"  attempt{attempt}: {type(e).__name__} {time.time()-t0:.2f}s")
    finally:
        try: s.close()
        except: pass
    time.sleep(2)
