//
//  ave2_gate.m — 区分 AVE2 的 NotPermitted 到底是「沙箱拒绝」还是「provider 被独占」
//
//  背景（本轮新发现）：
//    1) KC 里 com.apple.security.iokit-user-client-class 白名单只有 5 个类
//       (IOBorealisOwl / IOTimeSyncIUserClient / DomainUserClient / PTPManagerUserClient /
//        ClockManagerUserClient)，**AVE2 不在其中** ⇒ NotPermitted 不是 entitlement 挡的
//    2) AVE2 自己的日志池里有两处 "IOService::open failed" + "resOpen == 0" 断言
//       xref 到 0x8a5baa0 段，反汇编看到 vtable+0x2d0 的 blraa（PAC disc 0xccfb，
//       x0=this, x1=0）返回 bool —— 即 AVE2 user client 打开时**自己会 open provider**
//
//  ⇒ 两种可能，性质完全不同：
//    A. sandbox `iokit-open` 拒绝（profile 里没有 ave2 条目）→ 要改 profile
//    B. IOService::open(provider) 失败（provider 已被 mediaserverd/相机/视频占用）→ 换时机可能就通
//
//  本 PoC 要区分 A 和 B：
//    Phase 1  冷启动立刻 open（最早时机，此时别的进程还没抢）
//    Phase 2  全部 type 0..15 各试一次，打印原始 kern_return_t
//    Phase 3  对成功的 type，立刻 close 再 reopen（验证独占性）
//    Phase 4  延迟重试（20 次 × 200ms），看有没有时间窗口
//    Phase 5  查 provider 与 service 的 IORegistry 属性（IOUserClientCount / IOBusyState 等）
//
//  判读：
//    · 冷启动成功 / 某种 type 成功     ⇒ **B（资源冲突）**，AVE2 活了，可以直接推 64747
//    · 全部 type 全 NotPermitted       ⇒ 倾向 A，等 OTA payload 解出 sandbox profile 再定
//    · 出现 Busy / ExclusiveAccess     ⇒ 明确是 B
//
//  安全性：只 open/close，不发任何 selector，不碰 AVE2 的功能路径。零风险。
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

// ★ 修正后的 IOKit 错误码表（之前把 0xe00002c2 误记成 NotAttached）
static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "SUCCESS";
        case 0xe00002b0: return "NoSuchClass";
        case 0xe00002bb: return "NoMemory";
        case 0xe00002bc: return "Error";
        case 0xe00002bd: return "NoMemory2";
        case 0xe00002be: return "NoResources";
        case 0xe00002bf: return "IPCError";
        case 0xe00002c0: return "NoDevice";
        case 0xe00002c1: return "NotPrivileged";
        case 0xe00002c2: return "BadArgument";      // ★ 不是 NotAttached
        case 0xe00002c3: return "LockedRead";
        case 0xe00002c4: return "LockedWrite";
        case 0xe00002c5: return "ExclusiveAccess";  // ★ B 的关键信号
        case 0xe00002c6: return "BadMessageID";
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c8: return "VMError";
        case 0xe00002c9: return "InternalError";
        case 0xe00002ca: return "IOError";
        case 0xe00002cb: return "CannotLock";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002cd: return "NotReadable";
        case 0xe00002ce: return "NotWritable";
        case 0xe00002cf: return "NotAligned";
        case 0xe00002d0: return "BadMedia";
        case 0xe00002d1: return "StillOpen";
        case 0xe00002d2: return "RLDError";
        case 0xe00002d3: return "DMAError";
        case 0xe00002d4: return "Busy";             // ★ B 的关键信号
        case 0xe00002d5: return "Timeout";
        case 0xe00002d6: return "Offline";
        case 0xe00002d7: return "NotReady";
        case 0xe00002d8: return "NotAttached";      // ★ 真正的 NotAttached
        case 0xe00002d9: return "NoChannels";
        case 0xe00002e2: return "NotPermitted";     // ★ A 的信号
        case 0xe00002e3: return "NotTerminated";
        case 0xe00002f0: return "NotFound";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"AVE2GATE %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ave2gate.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightBold];
        }
    });
}

// 打印一个 OSDictionary 里关心的键
static void dump_props(io_object_t obj, const char *which)
{
    CFMutableDictionaryRef props = NULL;
    kern_return_t kr = IORegistryEntryCreateCFProperties(obj, &props, kCFAllocatorDefault, 0);
    if (kr != KERN_SUCCESS || !props) {
        L(@"  [%@] IORegistryEntryCreateCFProperties -> 0x%x", @(which), (uint32_t)kr);
        return;
    }
    NSDictionary *d = (__bridge_transfer NSDictionary *)props;
    NSArray *keys = @[@"IOUserClientCount", @"IOBusyState", @"IOOpenCount", @"IOClass",
                      @"IOProviderClass", @"IOMatchedAtBoot", @"CurrentPowerState",
                      @"IOCommandGateCount", @"IOServiceDEXTEntitlements",
                      @"IOUserClientClass", @"IOKitDebug"];
    NSMutableArray *found = [NSMutableArray array];
    for (NSString *k in keys) {
        id v = d[k];
        if (v) [found addObject:[NSString stringWithFormat:@"%@=%@", k, v]];
    }
    if (found.count) {
        L(@"  [%@] %@", @(which), [found componentsJoinedByString:@"  "]);
    } else {
        L(@"  [%@] （关心的键都没出现，属性数=%lu）", @(which), (unsigned long)d.count);
    }
    // 把用户可见的额外键也列出来，方便看独占状态
    NSArray *extraKeys = @[@"IOUserClientCreator", @"IOPlatformDevice", @"compatible",
                           @"device_type", @"pre-loaded", @"iommu-parent"];
    for (NSString *k in extraKeys) {
        id v = d[k];
        if (v) L(@"         %@ = %@", k, v);
    }
}

static void run(void)
{
    L(@"===== AVE2 gate probe (A: sandbox vs B: provider busy) =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());

    // ---------- Phase 1: 冷启动立刻 open ----------
    L(@"");
    L(@"=== Phase 1: 冷启动立刻 open（最早时机）===");

    CFMutableDictionaryRef m = IOServiceMatching("AppleAVE2Driver");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"  service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) {
        L(@"  AppleAVE2Driver 没匹配到！服务名可能变了");
        SetStatus(@"没找到 AppleAVE2Driver");
        return;
    }

    dump_props(svc, "service");

    // provider 属性（"ave2" 设备节点）
    io_object_t parent = 0;
    if (IORegistryEntryGetParentEntry(svc, kIOServicePlane, &parent) == KERN_SUCCESS && parent) {
        io_name_t nm; nm[0] = 0;
        IORegistryEntryGetName(parent, nm);
        L(@"  provider = %s (0x%08x)", nm, parent);
        dump_props(parent, "provider");
        IOObjectRelease(parent);
    }

    // ---------- Phase 2: 全部 type 0..15 ----------
    L(@"");
    L(@"=== Phase 2: type 0..15 各试一次（记录原始返回码）===");
    int okTypes[32]; int okCount = 0;
    for (uint32_t t = 0; t <= 15; t++) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        if (kr == KERN_SUCCESS) {
            L(@"  type %2u -> SUCCESS   conn=0x%08x", t, conn);
            if (okCount < 32) okTypes[okCount++] = (int)t;
            IOServiceClose(conn);
        } else {
            L(@"  type %2u -> 0x%08x %s", t, (uint32_t)kr, kr_name(kr));
        }
    }
    L(@"  成功的 type: %d 个", okCount);

    // ---------- Phase 3: 对成功的 type，close 后立刻 reopen ----------
    if (okCount > 0) {
        L(@"");
        L(@"=== Phase 3: 成功的 type 做 close→reopen（验证是否独占）===");
        for (int i = 0; i < okCount; i++) {
            uint32_t t = (uint32_t)okTypes[i];
            io_connect_t c1 = MACH_PORT_NULL, c2 = MACH_PORT_NULL;
            kern_return_t k1 = IOServiceOpen(svc, mach_task_self(), t, &c1);
            kern_return_t k2 = IOServiceOpen(svc, mach_task_self(), t, &c2);
            L(@"  type %u: 1st=0x%x %s  2nd(不关第一个)=0x%x %s",
              t, (uint32_t)k1, kr_name(k1), (uint32_t)k2, kr_name(k2));
            if (c1) IOServiceClose(c1);
            if (c2) IOServiceClose(c2);
        }
    }

    // ---------- Phase 4: 延迟重试 ----------
    L(@"");
    L(@"=== Phase 4: 延迟重试（20 × 200ms，type=0 与新增的 15/16）===");
    int hitType = -1;
    for (int round = 0; round < 20; round++) {
        uint32_t tries[3] = {0, 15, 16};
        for (int j = 0; j < 3; j++) {
            io_connect_t c = MACH_PORT_NULL;
            kern_return_t kr = IOServiceOpen(svc, mach_task_self(), tries[j], &c);
            if (kr == KERN_SUCCESS) {
                L(@"  round %2d type %u -> SUCCESS conn=0x%08x", round, tries[j], c);
                if (hitType < 0) hitType = (int)tries[j];
                IOServiceClose(c);
            } else if (round % 5 == 0) {
                L(@"  round %2d type %u -> 0x%08x %s", round, tries[j], (uint32_t)kr, kr_name(kr));
            }
        }
        usleep(200 * 1000);
    }
    L(@"  延迟重试命中的 type: %d", hitType);

    // ---------- Phase 5: 再查一次属性 ----------
    L(@"");
    L(@"=== Phase 5: 再查属性（对比 Phase 1）===");
    dump_props(svc, "service-after");

    // ---------- 汇总 ----------
    L(@"");
    L(@"===== 判读 =====");
    if (okCount > 0 || hitType >= 0) {
        L(@"  ★★ 有 type 打开成功 ⇒ 结论 B（不是权限，是时机/资源）");
        L(@"     AVE2 的 64747 机制可以立刻推进（selector 4/5 = IO_Prepare / IO_Start）");
    } else {
        L(@"  全部 type 都失败（请看上面的具体码）：");
        L(@"    · 若全是 NotPermitted(0xe00002e2)  ⇒ 倾向 A（sandbox 拒绝），等 payload 解出 profile");
        L(@"    · 若出现 Busy/ExclusiveAccess      ⇒ B（被占用），关掉相机/视频再试");
        L(@"    · 若出现 NotPrivileged(0xe00002c1) ⇒ 需要 entitlement（但白名单里没有 AVE2，所以存疑）");
    }
    L(@"");
    L(@"  同时请让 PC 端跑: python -m pymobiledevice3 syslog live");
    L(@"  搜 'IOService::open failed' / 'AVE' —— 有就是 B（provider open 失败），没有更像 A");

    IOObjectRelease(svc);
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
    if (!gQ) gQ = dispatch_queue_create("ave2gate.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 55, self.window.bounds.size.width - 16, 40)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"AVE2 gate probe...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 100, self.window.bounds.size.width, h - 100)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    [vc.view addSubview:gView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    // 尽早跑（不等到 viewDidAppear），抢最早时机
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
