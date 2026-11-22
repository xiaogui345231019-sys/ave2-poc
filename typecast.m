//
//  typecast.m — 扩展 type 扫描 + 对已放行目标做 selector 探测
//
//  起因（kextscan 普查结论）：
//    对照组 7/7 正确 ⇒ sandbox 白名单是全局静态的
//    AVE2 = 纯沙箱拒绝（NotPermitted × 10 次重试，无时间窗口）——A 路线定案
//
//    ★ 关键发现：`Unsupported(0xe00002c7)` ≠ 被拒！
//      它意味着请求**已通过 mac_iokit_check_open_service**，只是 newUserClient 里
//      没有该 type 的分支。所以这三个是「白名单已放行，type 没试对」：
//        AppleH13CameraInterface (IOClass=AppleH13CamIn)
//        AppleAVD                (IOClass=AppleAVD)
//        AppleSPU                (IOClass=AppleSPU)
//
//    ★★ 另一个：AppleM2ScalerCSCDriver type 0/1/2/3 **全部 SUCCESS**
//      图像缩放/色彩空间转换驱动，从未分析过。
//
//  本包做三件事：
//    A. 对 4 个目标试 type 0..15（找出 H13Camera/AVD/SPU 的正确 type）
//    B. 对每个「能打开」的 (目标, type) 做 scalar selector 0..24 探测
//    C. 对能打开的再试 struct selector 0..12 × {0x30, 0x58, 0x100} 三种尺寸
//       （JPEG 的教训：structureInputSize 必须精确匹配声明值，0 会得 BadArgument）
//
//  安全性：只 open + 调 selector，不传有效数据、不建 IOSurface、不制造 UAF。
//        最坏结果是某个 selector 返回错误码或驱动记录一次失败。零 panic 风险。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static UILabel       *gStatus = nil;
static dispatch_queue_t gQ = nil;

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "SUCCESS";
        case 0xe00002b0: return "NoSuchClass";
        case 0xe00002bc: return "Error";
        case 0xe00002be: return "NoResources";
        case 0xe00002c0: return "NoDevice";
        case 0xe00002c1: return "NotPrivileged";
        case 0xe00002c2: return "BadArgument";
        case 0xe00002c5: return "ExclusiveAccess";
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c9: return "InternalError";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002d4: return "Busy";
        case 0xe00002d8: return "NotAttached";
        case 0xe00002e2: return "NotPermitted";
        case 0xe00002f0: return "NotFound";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"TYPECAST %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"typecast.log"];
    FILE *f = fopen([p UTF8String], "a");
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
        if (gStatus) {
            gStatus.text = s;
            gStatus.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
        }
    });
}

typedef struct { const char *name; const char *alt; } tgt_t;

static tgt_t g_tgts[] = {
    { "AppleM2ScalerCSCDriver",     "AppleM2Scaler" },
    { "AppleH13CameraInterface",    "AppleH13CamIn" },
    { "AppleAVD",                   NULL },
    { "AppleSPU",                   NULL },
    { "AppleJPEGDriver",            NULL },   // 对照（已知可开、已知能解码）
};

// 探测一个 (svc, type) 的 selector 面
static void probe_selectors(io_service_t svc, uint32_t type, const char *tname)
{
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
    if (kr != KERN_SUCCESS) return;

    L(@"    --- %s type=%u 的 selector 探测 ---", tname, type);

    // A. scalar selector 0..24
    char line[512]; int o = 0;
    o += snprintf(line+o, sizeof(line)-o, "      scalar:");
    int succS[32], nS = 0;
    for (uint32_t sel = 0; sel <= 24; sel++) {
        uint64_t out[8]; memset(out, 0, sizeof(out));
        uint32_t outCnt = 8;
        kern_return_t r = IOConnectCallScalarMethod(conn, sel, NULL, 0, out, &outCnt);
        if (r == KERN_SUCCESS) { if (nS < 32) succS[nS++] = (int)sel; }
        if (o < (int)sizeof(line)-20) o += snprintf(line+o, sizeof(line)-o, " %s", kr_name(r));
    }
    L(@"%s", line);

    if (nS > 0) {
        char b[128]; int p2 = 0;
        p2 += snprintf(b+p2, sizeof(b)-p2, "      ★ scalar 成功 sel:");
        for (int i = 0; i < nS && p2 < 120; i++) p2 += snprintf(b+p2, sizeof(b)-p2, " %d", succS[i]);
        L(@"%s", b);
    }

    // B. struct selector 0..12 × 三种尺寸
    for (int si = 0; si < 3; si++) {
        size_t szs[3] = {0x30, 0x58, 0x100};
        size_t sz = szs[si];
        uint8_t *in = calloc(sz, 1);
        if (!in) continue;
        char l2[512]; int q = 0;
        q += snprintf(l2+q, sizeof(l2)-q, "      struct[0x%02zx]:", sz);
        for (uint32_t sel = 0; sel <= 12; sel++) {
            uint8_t out[0x200]; memset(out, 0, sizeof(out));
            size_t os = sizeof(out);
            kern_return_t r = IOConnectCallStructMethod(conn, sel, in, sz, out, &os);
            if (q < (int)sizeof(l2)-20) q += snprintf(l2+q, sizeof(l2)-q, " %s", kr_name(r));
        }
        L(@"%s", l2);
        free(in);
    }

    L(@"    --- 结束 ---");
    IOServiceClose(conn);
}

static void run(void)
{
    L(@"===== typecast: type 0..15 + selector probe =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    int nt = sizeof(g_tgts)/sizeof(g_tgts[0]);
    for (int i = 0; i < nt; i++) {
        const char *name = g_tgts[i].name;
        const char *alt  = g_tgts[i].alt;

        L(@"=== %s ===", name);
        SetStatus([NSString stringWithFormat:@"扫描 %@", @(name)]);

        CFMutableDictionaryRef m = IOServiceMatching(name);
        io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
        if (svc == MACH_PORT_NULL && alt) {
            m = IOServiceMatching(alt);
            svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
        }
        if (svc == MACH_PORT_NULL) {
            L(@"  [未匹配到 service]");
            L(@"");
            continue;
        }

        // A. 全部 type 0..15
        int okTypes[16]; int nOk = 0;
        char buf[600]; int o = 0;
        o += snprintf(buf+o, sizeof(buf)-o, "  type:");
        for (uint32_t t = 0; t <= 15; t++) {
            io_connect_t c = MACH_PORT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &c);
            if (kr == KERN_SUCCESS) {
                if (nOk < 16) okTypes[nOk++] = (int)t;
                IOServiceClose(c);
            }
            if (o < (int)sizeof(buf)-24) o += snprintf(buf+o, sizeof(buf)-o, " %u:%s", t, kr_name(kr));
        }
        L(@"%s", buf);

        if (nOk > 0) {
            char b2[200]; int p3 = 0;
            p3 += snprintf(b2+p3, sizeof(b2)-p3, "  ★ 可开 type:");
            for (int k = 0; k < nOk && p3 < 180; k++) p3 += snprintf(b2+p3, sizeof(b2)-p3, " %d", okTypes[k]);
            L(@"%s", b2);

            // B/C. 对每个可开 type 做 selector 探测
            //     M2Scaler / JPEG 只探 type 0（避免重复太多次）
            int probeCount = (nOk > 2) ? 1 : nOk;
            for (int k = 0; k < probeCount; k++) {
                probe_selectors(svc, (uint32_t)okTypes[k], name);
            }
        }

        IOObjectRelease(svc);
        L(@"");
    }

    SetStatus(@"完成，看日志");
    L(@"===== done =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("typecast.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"typecast...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 90, self.window.bounds.size.width, h - 90)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:6] ?: [UIFont systemFontOfSize:6];
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
