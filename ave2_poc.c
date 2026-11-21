//
//  ave2_poc.c — AppleAVE2 / CVE-2026-64747 真机 PoC（阶段 0，纯 C 版，供交叉编译）
//
//  为什么有纯 C 版：GitHub Actions 的 macOS runner 排队极慢，改用 ubuntu-latest +
//  Theos SDK 交叉编译。Objective-C 需要更多运行时依赖，纯 C + CoreFoundation 足够。
//
//  目标设备：iPhone13,4 / iOS 18.7.2 (22H124) / A14 t8101
//  本地实测：IOClass = AppleAVE2Driver，IONameMatch = "ave2"，bundle = com.apple.driver.AppleAVE2
//  离线实测：user client 类名 = AppleAVE2UserClient（方法簇 0xfffffff008a4b2c8..0xfffffff008a4cf80）
//
//  阶段 0 只做三件事，全部只读/无副作用：
//    1. IOServiceMatching("AppleAVE2Driver") 拿 service  —— 验证沙箱 iokit-open 白名单
//    2. IOServiceOpen type 0..8 循环                      —— 确定 newUserClient 支持的 type
//    3. 打开成功后调 selector 0 的空方法                    —— 确认 user client 可用
//  不发送任何 structureInput，不触发编码/解码，不可能造成越界。
//

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "KERN_SUCCESS";
        case 0xe00002bc: return "kIOReturnError";
        case 0xe00002c1: return "kIOReturnNotReady";
        case 0xe00002c2: return "kIOReturnNotAttached";
        case 0xe00002c7: return "kIOReturnUnsupported";
        case 0xe00002c9: return "kIOReturnBadArgument";
        case 0xe00002d5: return "kIOReturnBusy";
        case 0xe00002d6: return "kIOReturnTimeout";
        case 0xe00002e2: return "kIOReturnNotPermitted";
        case 0xe00002e3: return "kIOReturnNotPrivileged";
        case 0xe00002f0: return "kIOReturnNotFound";
        case 0xe00003e9: return "AVE2_PRIVATE_FAIL(0xe00003e9)";
        default:         return "?";
    }
}

static void print_kr(const char *what, kern_return_t kr)
{
    printf("    %-24s kr=0x%08x  %s\n", what, (uint32_t)kr, kr_name(kr));
}

static void dump_props(io_registry_entry_t entry)
{
    CFMutableDictionaryRef props = NULL;
    kern_return_t kr = IORegistryEntryCreateCFProperties(entry, &props, kCFAllocatorDefault, 0);
    if (kr != KERN_SUCCESS || props == NULL) {
        printf("  [props] IORegistryEntryCreateCFProperties failed kr=0x%x\n", (uint32_t)kr);
        return;
    }
    CFIndex n = CFDictionaryGetCount(props);
    printf("  [props] %ld keys\n", (long)n);

    const void **keys = (const void **)malloc(sizeof(void *) * (size_t)n);
    const void **vals = (const void **)malloc(sizeof(void *) * (size_t)n);
    if (keys && vals) {
        CFDictionaryGetKeysAndValues(props, keys, vals);
        for (CFIndex i = 0; i < n; i++) {
            const char *k = NULL;
            char kbuf[96] = {0};
            if (CFGetTypeID(keys[i]) == CFStringGetTypeID()) {
                CFStringGetCString((CFStringRef)keys[i], kbuf, sizeof(kbuf), kCFStringEncodingUTF8);
                k = kbuf;
            }
            CFStringRef vs = CFCopyDescription(vals[i]);
            char vbuf[256] = {0};
            if (vs) {
                CFStringGetCString(vs, vbuf, sizeof(vbuf), kCFStringEncodingUTF8);
                CFRelease(vs);
            }
            printf("    %-30s = %s\n", k ? k : "?", vbuf);
        }
    }
    free(keys);
    free(vals);
    CFRelease(props);
}

int main(int argc, char *argv[])
{
    printf("\n=====================================================\n");
    printf("  AVE2 PoC — stage 0 (enumerate / type probe)\n");
    printf("  build: " __DATE__ " " __TIME__ "\n");
    printf("=====================================================\n");
    printf("  uid=%d  euid=%d  pid=%d\n", getuid(), geteuid(), getpid());
    printf("\n");

    printf("[1] IOServiceMatching(\"AppleAVE2Driver\")\n");
    CFMutableDictionaryRef match = IOServiceMatching("AppleAVE2Driver");
    if (match == NULL) {
        printf("    FAILED: IOServiceMatching returned NULL\n");
        return 10;
    }
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, match);
    printf("    service = 0x%08x\n", svc);
    if (svc == MACH_PORT_NULL) {
        printf("    FAILED: no matching service\n");
        printf("    -> sandbox iokit-open whitelist likely does not cover AppleAVE2Driver\n");
        return 11;
    }
    dump_props(svc);

    printf("\n[2] IOServiceOpen type sweep 0..8\n");
    io_connect_t good_conn = MACH_PORT_NULL;
    uint32_t     good_type = 0xFFFFFFFF;

    for (uint32_t t = 0; t <= 8; t++) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        printf("  type=%u\n", t);
        print_kr("IOServiceOpen", kr);
        if (kr == KERN_SUCCESS) {
            printf("    >>> OPEN OK  type=%u conn=0x%08x\n", t, conn);
            if (good_conn == MACH_PORT_NULL) {
                good_conn = conn;
                good_type = t;
            } else {
                IOServiceClose(conn);
            }
        }
    }

    if (good_conn == MACH_PORT_NULL) {
        printf("\n  no type opened successfully\n");
        IOObjectRelease(svc);
        return 12;
    }

    printf("\n[3] IOConnectCallScalarMethod(conn=0x%x, selector=0, no args)\n", good_conn);
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
