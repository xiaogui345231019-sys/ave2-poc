KC = r"E:\IOS18.7.2\work\fw\a14_18.7.2_22H124\kernelcache.release.iphone13.raw"
data = open(KC,"rb").read()
for kw in [b"mac_iokit_check_open_service", b"mac_iokit_check_open", b"iokit_check_open",
           b"sb_evaluate", b"sandbox_check", b"mac_policy_ops", b"clientHasPrivilege",
           b"IOService::open", b"is_io_service_open_extended"]:
    n = data.count(kw)
    print(f"  {kw.decode():38s} {n}")
