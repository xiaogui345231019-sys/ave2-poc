import os, sys, time, threading, urllib.request, concurrent.futures

URL = "https://secure-appldnld.apple.com/itunes12/142-28289-20261026-6acff6c8-72eb-4045-84eb-fd35239ac645/iTunes64Setup.exe"
OUT = r"C:\Temp\iTunes64Setup.exe"
TOTAL = 202558432
THREADS = 16
PROXY = "http://127.0.0.1:7890"

# route through system proxy like the browser would
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))

chunk = TOTAL // THREADS + 1
lock = threading.Lock()
done = [0]

def fetch(idx):
    start = idx * chunk
    end = min(start + chunk - 1, TOTAL - 1)
    if start > end:
        return
    for attempt in range(4):
        try:
            req = urllib.request.Request(URL, headers={"Range": f"bytes={start}-{end}"})
            with opener.open(req, timeout=60) as r:
                data = r.read()
            if len(data) != end - start + 1:
                raise IOError(f"short {len(data)} vs {end-start+1}")
            with lock:
                with open(OUT, "r+b") as f:
                    f.seek(start); f.write(data)
                done[0] += len(data)
                pct = 100.0 * done[0] / TOTAL
                print(f"  [{pct:5.1f}%] {done[0]/1048576:.1f} MB", flush=True)
            return
        except Exception as e:
            if attempt == 3:
                print(f"  chunk {idx} FAILED: {e}", flush=True)

# preallocate
with open(OUT, "wb") as f:
    f.truncate(TOTAL)

t0 = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
    list(ex.map(fetch, range(THREADS)))
dt = time.time() - t0
print(f"DONE {done[0]/1048576:.1f} MB in {dt:.1f}s = {done[0]/dt/1024:.0f} KB/s")
