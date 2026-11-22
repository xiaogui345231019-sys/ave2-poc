//
//  gpuscan.m — 盲扫 GPU / ANE / KeyStore / HID 的 selector 面
//
//  起因（typecast2 的突破）：
//    203 IOClass × type0-15 扫出 13 个可 open，其中最有价值的两个是新增的：
//      AGXAcceleratorG13P_B0   type=1   ← GPU（type0 = Unsupported）
//      H11ANEIn                type=1   ← ANE 神经引擎（type0 = Unsupported）
//    另外 6 个 HID 类都是 type=2，AppleKeyStore 是 type=0。
//
//  本包盲扫（不等离线解表），用「返回码分类」判断 selector 是否存在：
//    Unsupported  = 该 selector 不存在
//    BadArgument  = selector 存在、参数无效（全零请求很正常）
//    SUCCESS      = 调通了
//    其他         = 记下来
//
//  尺寸策略（JPEG 的教训）：checkStructureInputSize 必须精确匹配，
//    所以对每个 selector 试多档：0x18 / 0x30 / 0x58 / 0x80 / 0x100 / 0x400 / 0x1000
//
//  安全性：全部传全零结构体、无有效句柄、无 surface。最坏是返回错误码。
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
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"gpuscan.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
        }
    });
}

typedef struct { const char *name; uint32_t type; const char *tag; } tgt_t;

static tgt_t g_tgts[] = {
    { "AGXAcceleratorG13P_B0",  1, "GPU"      },
    { "H11ANEIn",               1, "ANE"      },
    { "AppleKeyStore",          0, "KeyStore" },
    { "AppleM68Buttons",        2, "HID-btn"  },
    { "AppleSPUHIDDriver",      2, "HID-spu"  },
    { "AOPTouchHIDDriver",      2, "HID-touch"},
    { "AppleProxHIDEventDriver",2, "HID-prox" },
    { "AppleSPUCT725",          2, "HID-ct"   },
};

// 扫一个 (svc, type) 的 selector 面
static void scan_target(const char *name, uint32_t type, const char *tag)
{
    L(@"");
    L(@"========== %s (%s) type=%u ==========", name, tag, type);
    SetStatus([NSString stringWithFormat:@"%s t%u", tag, type]);

    CFMutableDictionaryRef m = IOServiceMatching(name);
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    if (svc == MACH_PORT_NULL) { L(@"  未匹配到 service"); return; }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), type, &conn);
    L(@"  open(type=%u) -> 0x%08x %s", type, (uint32_t)kr, kr_name(kr));
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { L(@"  打不开，跳过"); return; }

    // ---- A. scalar selector 0..31 ----
    L(@"  --- scalar sel 0..31 ---");
    char line[1024]; int o = 0;
    int scalarExist[32], nSE = 0;
    o += snprintf(line+o, sizeof(line)-o, "    ");
    for (uint32_t sel = 0; sel <= 31; sel++) {
        uint64_t out[8]; memset(out, 0, sizeof(out));
        uint32_t outCnt = 8;
        kern_return_t r = IOConnectCallScalarMethod(conn, sel, NULL, 0, out, &outCnt);
        // Unsupported = 不存在；其他 = 存在
        if ((uint32_t)r != 0xe00002c7) {
            if (nSE < 32) scalarExist[nSE++] = (int)sel;
        }
        if (o < (int)sizeof(line)-24)
            o += snprintf(line+o, sizeof(line)-o, "%u:%c ", sel,
                          (uint32_t)r == 0xe00002c7 ? '.' :
                          (uint32_t)r == 0x0 ? 'S' :
                          (uint32_t)r == 0xe00002c2 ? 'B' : 'x');
    }
    L(@"%s", line);
    L(@"    图例: S=SUCCESS  B=BadArgument  x=其他  .=Unsupported(不存在)");
    if (nSE > 0) {
        char b[256]; int p2 = 0;
        p2 += snprintf(b+p2, sizeof(b)-p2, "  ★ 存在的 scalar selector:");
        for (int i = 0; i < nSE && p2 < 240; i++) p2 += snprintf(b+p2, sizeof(b)-p2, " %d", scalarExist[i]);
        L(@"%s", b);
    }

    // ---- B. struct selector 0..20 × 多档尺寸 ----
    L(@"  --- struct sel 0..20 × 尺寸 ---");
    size_t sizes[] = {0x18, 0x30, 0x58, 0x80, 0x100, 0x400, 0x1000};
    int nSizes = (int)(sizeof(sizes)/sizeof(sizes[0]));
    for (int si = 0; si < nSizes; si++) {
        size_t sz = sizes[si];
        uint8_t *in = calloc(sz, 1);
        if (!in) continue;
        char l2[1024]; int q = 0;
        int hits[24], nH = 0;
        q += snprintf(l2+q, sizeof(l2)-q, "    [0x%04zx] ", sz);
        for (uint32_t sel = 0; sel <= 20; sel++) {
            uint8_t out[0x200]; memset(out, 0, sizeof(out));
            size_t os = sizeof(out);
            kern_return_t r = IOConnectCallStructMethod(conn, sel, in, sz, out, &os);
            if ((uint32_t)r != 0xe00002c7 && nH < 24) hits[nH++] = (int)sel;
            if (q < (int)sizeof(l2)-8)
                q += snprintf(l2+q, sizeof(l2)-q, "%c",
                              (uint32_t)r == 0xe00002c7 ? '.' :
                              (uint32_t)r == 0x0 ? 'S' :
                              (uint32_t)r == 0xe00002c2 ? 'B' : 'x');
        }
        L(@"%s", l2);
        if (nH > 0) {
            char b2[256]; int p3 = 0;
            p3 += snprintf(b2+p3, sizeof(b2)-p3, "           存在的 sel:");
            for (int i = 0; i < nH && p3 < 240; i++) p3 += snprintf(b2+p3, sizeof(b2)-p3, " %d", hits[i]);
            L(@"%s", b2);
        }
        free(in);
        usleep(60 * 1000);
    }

    IOServiceClose(conn);
}

static void run(void)
{
    L(@"===== GPU / ANE / KeyStore / HID selector 盲扫 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());

    int n = sizeof(g_tgts)/sizeof(g_tgts[0]);
    for (int i = 0; i < n; i++) {
        scan_target(g_tgts[i].name, g_tgts[i].type, g_tgts[i].tag);
        sleep(1);
    }

    L(@"");
    L(@"===== 判读 =====");
    L(@"  · 图例: S=SUCCESS  B=BadArgument(=selector存在)  x=其他  .=Unsupported(=不存在)");
    L(@"  · 存在的 selector 数量 = 该服务的真实攻击面宽度");
    L(@"  · 若某 selector 在某一档尺寸是 B、另一档是 x，说明尺寸匹配不同");
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
    if (!gQ) gQ = dispatch_queue_create("gpuscan.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"gpuscan...";
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
