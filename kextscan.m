//
//  kextscan.m — 一次性普查「沙箱里到底能打开哪些 kext 的 user client」
//
//  起因（沙箱语法已查明）：
//    OTA payload.002 等抽出的 .sb 显示 iokit-open 是**按类名白名单**：
//        (allow iokit-open
//            (iokit-registry-entry-class "AppleKeyStoreUserClient")
//            (iokit-user-client-class    "AppleNVMeEANUC" "AvpFairPlayUserClient"))
//    ⇒ 不在列表里默认拒。真机已反推：IOSurface/IOMFB/JPEG/IOHID 在白名单，
//      AVE2/AMFI/SMC/IOAESAccelerator 不在。
//
//  本包回答两件事：
//    C. 子代理给的新候选（AppleH13CameraInterface / AppleAVD / RTBuddy 等）在不在白名单里
//                                                   —— 若在，那是比 AVE2 更好的目标
//    AVE2 到底是 NotPermitted（沙箱拒）还是 Busy/ExclusiveAccess（provider 被占）
//                                                   —— 后者还有救，前者要绕
//
//  做法：对每个目标 × type 0..3 做 IOServiceOpen，记录**原始 kern_return_t**。
//       同时为 AVE2 额外 dump provider 属性（IOUserClientCount / IOBusyState）。
//       带对照组（已知可开 4 个 / 已知拒 3 个），任何异常都能立刻识别。
//
//  安全性：只 open/close，不调任何 selector，不进任何功能路径。零风险。
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
        case 0xe00002c5: return "ExclusiveAccess";   // ★ 占用信号
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c9: return "InternalError";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002d4: return "Busy";              // ★ 占用信号
        case 0xe00002d8: return "NotAttached";
        case 0xe00002e2: return "NotPermitted";      // ★ 沙箱拒绝
        case 0xe00002f0: return "NotFound";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"KXSCAN %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"kextscan.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightBold];
        }
    });
}

// 目标表：name = IOServiceMatching 用的类名；alt = 备用匹配名（可 NULL）；kind = 预期
typedef struct {
    const char *name;
    const char *alt;
    const char *expect;     // "OK" / "DENY" / "NEW"
} target_t;

static target_t g_targets[] = {
    // —— 对照组：已知可开 ——
    { "IOSurfaceRoot",              NULL,                        "OK"   },
    { "IOMobileFramebuffer",        NULL,                        "OK"   },
    { "AppleJPEGDriver",            NULL,                        "OK"   },
    { "IOHIDEventDriver",           NULL,                        "OK"   },
    // —— 对照组：已知拒 ——
    { "AppleMobileFileIntegrity",   NULL,                        "DENY" },
    { "AppleSMC",                   NULL,                        "DENY" },
    { "IOAESAccelerator",           NULL,                        "DENY" },
    // —— 重点：AVE2 ——
    { "AppleAVE2Driver",            "AppleAVE2",                 "NEW"  },
    // —— 子代理新候选 ——
    { "AppleH13CameraInterface",    "AppleH13CamIn",             "NEW"  },
    { "AppleAVD",                   "AppleAVDDecoder",           "NEW"  },
    { "RTBuddy",                    NULL,                        "NEW"  },
    // —— 补充：其他高价值 ——
    { "AppleM2ScalerCSCDriver",     "AppleM2Scaler",             "NEW"  },
    { "AppleJPEGDecodeDriver",      NULL,                        "NEW"  },
    { "AppleJPEGEncodeDriver",      NULL,                        "NEW"  },
    { "AppleProResDecoder",         NULL,                        "NEW"  },
    { "AppleMemTrace",              NULL,                        "NEW"  },
    { "IOGPUDevice",                "IOGPUFamily",               "NEW"  },
    { "AppleSEPManager",            "AppleSEPKeyStore",          "NEW"  },
    { "AppleBiometricSensor",       NULL,                        "NEW"  },
    { "AppleDCPAVController",       "AppleDCP",                  "NEW"  },
    { "AppleDisplayCrossbar",       NULL,                        "NEW"  },
    { "AppleHaptics",               "AppleHapticsDriver",        "NEW"  },
    { "AppleSPU",                   NULL,                        "NEW"  },
};

static void dump_props(io_object_t obj, const char *tag)
{
    CFMutableDictionaryRef props = NULL;
    if (IORegistryEntryCreateCFProperties(obj, &props, kCFAllocatorDefault, 0) != KERN_SUCCESS || !props)
        return;
    NSDictionary *d = (__bridge_transfer NSDictionary *)props;
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *k in @[@"IOUserClientCount", @"IOBusyState", @"IOOpenCount", @"IOClass",
                          @"CFBundleIdentifier", @"IOMatchedAtBoot", @"CurrentPowerState",
                          @"IOUserClientClass", @"IOProviderClass"]) {
        id v = d[k];
        if (v) [out addObject:[NSString stringWithFormat:@"%@=%@", k, v]];
    }
    if (out.count) L(@"      [%@] %@", @(tag), [out componentsJoinedByString:@"  "]);
}

typedef struct {
    char  name[64];
    int   found;
    int   okTypes[8];
    int   okCount;
    char  krStr[4][24];      // type 0..3 的错误码名
    int   krRaw[4];
} result_t;

static result_t g_res[64];
static int g_nres = 0;

static void probe_one(const char *name, const char *alt, const char *expect)
{
    result_t *r = &g_res[g_nres];
    strncpy(r->name, name, sizeof(r->name)-1);
    r->found = 0; r->okCount = 0;
    for (int i = 0; i < 4; i++) { r->krRaw[i] = -1; strcpy(r->krStr[i], "-"); }

    CFMutableDictionaryRef m = IOServiceMatching(name);
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    if (svc == MACH_PORT_NULL && alt) {
        m = IOServiceMatching(alt);
        svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    }
    if (svc == MACH_PORT_NULL) {
        L(@"  %-30s  [未匹配到]", name);
        g_nres++;
        return;
    }
    r->found = 1;

    // 属性
    dump_props(svc, name);

    // type 0..3
    for (uint32_t t = 0; t < 4; t++) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        r->krRaw[t] = (int)kr;
        strncpy(r->krStr[t], kr_name(kr), sizeof(r->krStr[t])-1);
        if (kr == KERN_SUCCESS) {
            if (r->okCount < 8) r->okTypes[r->okCount++] = (int)t;
            IOServiceClose(conn);
        }
    }

    // 判定
    const char *verdict;
    if (r->okCount > 0) verdict = "OPENABLE";
    else if (r->krRaw[0] == (int)0xe00002e2) verdict = "DENIED";
    else if (r->krRaw[0] == (int)0xe00002d4 || r->krRaw[0] == (int)0xe00002c5) verdict = "OCCUPIED";
    else if (r->krRaw[0] == 0) verdict = "OPENABLE";
    else verdict = "OTHER";

    // ★ 与预期对照
    const char *mark = "";
    if (strcmp(expect, "OK") == 0 && r->okCount > 0) mark = "  [对照正确]";
    else if (strcmp(expect, "OK") == 0 && r->okCount == 0) mark = "  [!! 对照反常]";
    else if (strcmp(expect, "DENY") == 0 && r->okCount == 0) mark = "  [对照正确]";
    else if (strcmp(expect, "DENY") == 0 && r->okCount > 0) mark = "  [!! 对照反常]";
    else if (strcmp(expect, "NEW") == 0 && r->okCount > 0) mark = "  ★★★ 新发现！";

    char okbuf[32] = "-";
    if (r->okCount > 0) {
        int o = 0;
        for (int i = 0; i < r->okCount && o < 30; i++) o += snprintf(okbuf+o, 30-o, "%s%d", i?"/":"", r->okTypes[i]);
    }

    L(@"  %-30s t0=%-15s t1=%-15s t2=%-15s t3=%-15s -> %-9s ok=[%s]%s",
      name, r->krStr[0], r->krStr[1], r->krStr[2], r->krStr[3], verdict, okbuf, mark);

    // AVE2 额外：查 provider
    if (strcmp(name, "AppleAVE2Driver") == 0) {
        io_object_t parent = 0;
        if (IORegistryEntryGetParentEntry(svc, kIOServicePlane, &parent) == KERN_SUCCESS && parent) {
            io_name_t nm; nm[0] = 0;
            IORegistryEntryGetName(parent, nm);
            L(@"      provider = %s", nm);
            dump_props(parent, "provider");
            IOObjectRelease(parent);
        }
    }

    IOObjectRelease(svc);
    g_nres++;
}

static void run(void)
{
    L(@"===== kext user-client reachability census =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());
    L(@"");

    // Phase 1：冷启动立刻测一次（抢最早时机）
    L(@"=== Phase 1: 冷启动立刻测（最早时机）===");
    SetStatus(@"Phase 1: 冷启动扫描...");
    int n = sizeof(g_targets)/sizeof(g_targets[0]);
    for (int i = 0; i < n; i++) {
        probe_one(g_targets[i].name, g_targets[i].alt, g_targets[i].expect);
    }

    // Phase 2：延迟重试 AVE2（看有没有时间窗口）
    L(@"");
    L(@"=== Phase 2: AVE2 延迟重试（10 × 300ms，看是否是时序问题）===");
    SetStatus(@"Phase 2: AVE2 重试...");
    CFMutableDictionaryRef m = IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    if (svc != MACH_PORT_NULL) {
        for (int round = 0; round < 10; round++) {
            io_connect_t c = MACH_PORT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &c);
            if (kr == KERN_SUCCESS) {
                L(@"  round %2d -> SUCCESS conn=0x%08x", round, c);
                IOServiceClose(c);
            } else if (round % 3 == 0) {
                L(@"  round %2d -> 0x%08x %s", round, (uint32_t)kr, kr_name(kr));
            }
            usleep(300 * 1000);
        }
        IOObjectRelease(svc);
    }

    // 汇总
    L(@"");
    L(@"===== 汇总 =====");
    L(@"");
    L(@"  [能打开的]");
    for (int i = 0; i < g_nres; i++) {
        if (g_res[i].found && g_res[i].okCount > 0)
            L(@"    %-30s type=%d (共%d个)", g_res[i].name, g_res[i].okTypes[0], g_res[i].okCount);
    }
    L(@"");
    L(@"  [NotPermitted — 沙箱拒绝]");
    for (int i = 0; i < g_nres; i++) {
        if (g_res[i].found && g_res[i].okCount == 0 && g_res[i].krRaw[0] == (int)0xe00002e2)
            L(@"    %-30s", g_res[i].name);
    }
    L(@"");
    L(@"  [OCCUPIED — 被占用，换时机可能就通]");
    for (int i = 0; i < g_nres; i++) {
        if (g_res[i].found && g_res[i].okCount == 0 &&
            (g_res[i].krRaw[0] == (int)0xe00002d4 || g_res[i].krRaw[0] == (int)0xe00002c5))
            L(@"    %-30s", g_res[i].name);
    }
    L(@"");
    L(@"  [其他错误]");
    for (int i = 0; i < g_nres; i++) {
        if (g_res[i].found && g_res[i].okCount == 0 &&
            g_res[i].krRaw[0] != (int)0xe00002e2 &&
            g_res[i].krRaw[0] != (int)0xe00002d4 &&
            g_res[i].krRaw[0] != (int)0xe00002c5)
            L(@"    %-30s t0=0x%08x %s", g_res[i].name, g_res[i].krRaw[0], g_res[i].krStr[0]);
    }
    L(@"");
    L(@"  [未匹配到 service]");
    for (int i = 0; i < g_nres; i++) {
        if (!g_res[i].found)
            L(@"    %-30s", g_res[i].name);
    }

    SetStatus(@"完成，看下方日志");
    L(@"");
    L(@"===== done =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("kextscan.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 36)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"kext census...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 94, self.window.bounds.size.width, h - 94)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    // 内容很宽，用小字号
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
