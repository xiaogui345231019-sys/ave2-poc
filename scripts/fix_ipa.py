import zipfile, os, shutil

src = r"C:\Temp\ave2_poc.ipa"
out = r"C:\Temp\ave2_poc_fixed.ipa"
work = r"C:\Temp\ipa_fix"

shutil.rmtree(work, ignore_errors=True)
os.makedirs(os.path.join(work, "Payload"), exist_ok=True)

# 1) unpack old (wrong layout)
with zipfile.ZipFile(src) as z:
    print("old members:", z.namelist())
    z.extractall(os.path.join(work, "old"))

old_app = os.path.join(work, "old", "ave2_poc.app")
new_app = os.path.join(work, "Payload", "ave2_poc.app")
shutil.copytree(old_app, new_app)

# 2) sanity: executable must be present and non-empty
exe = os.path.join(new_app, "ave2_poc")
print("exe size:", os.path.getsize(exe))
print("Info.plist size:", os.path.getsize(os.path.join(new_app, "Info.plist")))

# 3) repack with Payload/ at archive root
if os.path.exists(out): os.remove(out)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, dirs, files in os.walk(os.path.join(work, "Payload")):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, work)
            z.write(full, rel)
print("new members:", zipfile.ZipFile(out).namelist())
print("fixed ipa size:", os.path.getsize(out))
