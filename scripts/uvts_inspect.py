"""Inspect a PyInstaller-built UVTextureStudio exe: list PYZ modules + dump app-module constants.

Usage: python uvts_inspect.py <exe> <outdir>
"""
import dis
import marshal
import os
import struct
import sys
import types
import zlib

APP_PREFIXES = ("core", "ui", "main", "app", "services", "widgets", "utils")


def read_archive(exe: str):
    data = open(exe, "rb").read()
    i = data.rfind(b"MEI\014\013\012\013\016")
    if i < 0:
        raise SystemExit("no PyInstaller cookie")
    pkg_len, toc_pos, toc_len, pyvers = struct.unpack("!IIII", data[i + 8:i + 24])
    base = i + 88 - pkg_len
    toc = data[base + toc_pos: base + toc_pos + toc_len]
    entries = []
    j = 0
    while j < len(toc):
        elen, off, clen, ulen, cflag, typ = struct.unpack("!IIIIBc", toc[j:j + 18])
        name = toc[j + 18:j + elen].rstrip(b"\x00").decode("utf8", "replace")
        entries.append((name, typ, base + off, clen, ulen, cflag))
        j += elen
    return data, base, entries, pyvers


def load_pyz(data, entry):
    name, typ, off, clen, ulen, cflag = entry
    blob = data[off:off + clen]
    if cflag:
        blob = zlib.decompress(blob)
    return blob


def pyz_toc(blob):
    # header: PYZ\0 + pyc magic(4) + toc_offset(4) + ?(4)
    for cand in (8, 12, 16):
        try:
            off = struct.unpack("!i", blob[cand:cand + 4])[0]
            if 0 < off < len(blob):
                return marshal.loads(blob[off:])
        except Exception:
            continue
    raise SystemExit("cannot parse PYZ toc")


def walk(code, depth=0):
    yield code, depth
    for k in code.co_consts:
        if isinstance(k, types.CodeType):
            yield from walk(k, depth + 1)


def dump_code(code, fh):
    for c, depth in walk(code):
        args = c.co_varnames[:c.co_argcount]
        print("  " * depth + f"FUNC {c.co_name}({', '.join(args)})", file=fh)
        if c.co_names:
            print("  " * depth + "  NAMES: " + ", ".join(c.co_names), file=fh)
        for k in c.co_consts:
            if isinstance(k, types.CodeType):
                continue
            s = repr(k)
            if len(s) > 700:
                s = s[:700] + "..."
            print("  " * depth + "   CONST: " + s, file=fh)


def main():
    exe, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    data, base, entries, pyvers = read_archive(exe)
    print(f"python {pyvers}  entries {len(entries)}")
    report = []
    for name, typ, off, clen, ulen, cflag in entries:
        report.append(f"{typ.decode()} {name} len={clen}")
    open(os.path.join(outdir, "toc.txt"), "w", encoding="utf8").write("\n".join(report))

    pyz_entry = next(e for e in entries if e[0] == "PYZ.pyz")
    blob = load_pyz(data, pyz_entry)
    toc = pyz_toc(blob)
    mods = sorted(n for n, _ in toc)
    open(os.path.join(outdir, "modules.txt"), "w", encoding="utf8").write("\n".join(mods))
    app_mods = [m for m in mods if m.split(".")[0] in APP_PREFIXES]
    print("app modules:", app_mods)

    byname = {n: (t, o, l) for n, (t, o, l) in toc}
    for m in app_mods:
        typ, off, ln = byname[m]
        raw = blob[off:off + ln]
        try:
            code = marshal.loads(raw)
        except Exception:
            try:
                code = marshal.loads(zlib.decompress(raw))
            except Exception as exc:  # noqa: BLE001
                print("skip", m, exc)
                continue
        fn = os.path.join(outdir, m + ".txt")
        with open(fn, "w", encoding="utf8") as fh:
            dump_code(code, fh)
        print("dumped", m, "->", fn)

    # entry scripts (main / app entry) stored in CArchive
    for name, typ, off, clen, ulen, cflag in entries:
        if typ in (b"s", b"m") and not name.startswith(("pyimod", "pyi", "PYZ")):
            blob = data[off:off + clen]
            if cflag:
                blob = zlib.decompress(blob)
            try:
                code = marshal.loads(blob)
            except Exception:
                continue
            fn = os.path.join(outdir, f"__entry__{name}.txt")
            with open(fn, "w", encoding="utf8") as fh:
                dump_code(code, fh)
            print("dumped entry", name)


if __name__ == "__main__":
    main()
