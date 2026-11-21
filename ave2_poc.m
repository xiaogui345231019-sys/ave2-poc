//
//  ave2_poc.m — AppleAVE2 / CVE-2026-64747 真机 PoC（阶段 0：服务枚举 + type 探测）
//
//  目标设备：iPhone13,4 / iOS 18.7.2 (22H124) / A14 t8101
//  本地实测（IORegistry）：IOClass = AppleAVE2Driver，IONameMatch = "ave2"，bundle = com.apple.driver.AppleAVE2
//  离线实测（kext）：user client 类名 = AppleAVE2UserClient（方法簇 0xfffffff008a4b2c8..0xfffffff008a4cf80）
//
//  本阶段只做三件事，全部是只读/无副作用：
//    1. IOServiceMatching("AppleAVE2Driver") 能否拿到 service  —— 验证沙箱 iokit-open 白名单
//    2. 循环试 IOServiceOpen 的 type 0..8                      —— 确定 newUserClient 支持的 type
//    3. 打开成功后调一个 selectors = 0 的空方法                 —— 确认 user client 可用
//  不发送任何 structureInput，不触发编码/解码，不可能造成越界。
//

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>

#pragma mark - helpers

static void print_kr(const char *what, kern_return_t kr)
{
    uint32_t code = (uint32_t)kr;
    const char *known = "?";
    switch (code) {
        case 0:            known = "KERN_SUCCESS"; break;
        case 0xe00002c1:   known = "kIOReturnNotReady"; break;
        case 0xe00002c2:   known = "kIOReturnNotAttached"; break;
        case 0xe00002bc:   known = "kIOReturnError"; break;
        case 0xe00002c7:   known = "kIOReturnUnsupported"; break;
        case 0xe00002c9:   known = "kIOReturnBadArgument"; break;
        case 0xe00002d5:   known = "kIOReturnBusy"; break;
        case 0xe00002d6:   known = "kIOReturnTimeout"; break;
        case 0xe00002e2:   known = "kIOReturnNotPermitted"; break;
        case 0xe00002e3:   known = "kIOReturnNotPrivileged"; break;
        case 0xe00002f0:   known = "kIOReturnNotFound"; break;
        case 0xe00003e9:   known = "AVE2_PRIVATE_FAIL (CheckInfo family)"; break;
        default: break;
    }
    printf("    %-28s kr=0x%08x  %s\n", what, code, known);
}

static void dump_props(io_registry_entry_t entry)
{
    CFMutableDictionaryRef props = NULL;
    kern_return_t kr = IORegistryEntryCreateCFProperties(entry, &props, kCFAllocatorDefault, 0);
    if (kr != KERN_SUCCESS || props == NULL) {
        printf("  [props] IORegistryEntryCreateCFProperties failed kr=0x%x\n", (uint32_t)kr);
        return;
    }
    NSDictionary *d = (__bridge_transfer NSDictionary *)props;
    printf("  [props] %lu keys\n", (unsigned long)d.count);
    for (id k in [[d allKeys] sortedArrayUsingSelector:@selector(compare:)]) {
        id v = d[k];
        NSString *s = [v description];
        if (s.length > 160) s = [[s substringToIndex:160] stringByAppendingString:@"..."];
        printf("    %-32s = %s\n", [[k description] UTF8String], [s UTF8String]);
    }
}

#pragma mark - main

int main(int argc, char *argv[])
{
    @autoreleasepool {
        printf("\n");
        printf("=====================================================\n");
        printf("  AVE2 PoC — stage 0 (enumerate / type probe)\n");
        printf("=====================================================\n");
        printf("  uid=%d  euid=%d  pid=%d\n", getuid(), geteuid(), getpid());

        NSString *ver = [[UIDevice currentDevice] systemVersion];
        NSString *model = [[UIDevice currentDevice] model];
        printf("  device=%s  iOS=%s\n", [model UTF8String], [ver UTF8String]);
        printf("\n");

        // ---------- step 1: match the service ----------
        printf("[1] IOServiceMatching(\"AppleAVE2Driver\")\n");
        CFMutableDictionaryRef match = IOServiceMatching("AppleAVE2Driver");
        if (match == NULL) {
            printf("    FAILED: IOServiceMatching returned NULL\n");
            return 10;
        }
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, match);
        printf("    service = 0x%08x\n", svc);
        if (svc == MACH_PORT_NULL) {
            printf("    FAILED: no matching service.\n");
            printf("    Hint: if this is kIOReturnNotPermitted-related, the sandbox\n");
            printf("          iokit-open whitelist does not cover AppleAVE2Driver.\n");
            return 11;
        }
        dump_props(svc);

        // ---------- step 2: probe IOServiceOpen types ----------
        printf("\n[2] IOServiceOpen type sweep 0..8\n");
        io_connect_t good_conn = MACH_PORT_NULL;
        uint32_t     good_type = 0xFFFFFFFF;

        for (uint32_t t = 0; t <= 8; t++) {
            io_connect_t conn = MACH_PORT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
            printf("  type=%u\n", t);
            print_kr("IOServiceOpen", kr);
            if (kr == KERN_SUCCESS) {
                printf("    >>> OPEN OK: type=%u conn=0x%08x\n", t, conn);
                if (good_conn == MACH_PORT_NULL) {
                    good_conn = conn;
                    good_type = t;
                } else {
                    IOServiceClose(conn);
                }
            }
        }

        if (good_conn == MACH_PORT_NULL) {
            printf("\n  no type opened successfully.\n");
            IOObjectRelease(svc);
            return 12;
        }

        // ---------- step 3: harmless selector probe ----------
        printf("\n[3] IOConnectCallScalarMethod(conn=%u, selector=0, no args)\n", good_conn);
        {
            uint64_t out[16];
            memset(out, 0, sizeof(out));
            size_t outCnt = 16;
            kern_return_t kr = IOConnectCallScalarMethod(good_conn, 0, NULL, 0, out, &outCnt);
            print_kr("sel0", kr);
            printf("    outCnt=%zu\n", outCnt);
            for (size_t i = 0; i < outCnt && i < 16; i++)
                printf("      out[%zu] = 0x%016llx\n", i, (unsigned long long)out[i]);
        }

        IOServiceClose(good_conn);
        IOObjectRelease(svc);

        printf("\n=====================================================\n");
        printf("  stage 0 done. good_type=%u\n", good_type);
        printf("  next: stage 1 = sel 1 (IO_Open, structIn 0x6e0)\n");
        printf("=====================================================\n");
        return 0;
    }
}
