//
//  ave2open2.m — 按 ave2-gate 报告的三个正确姿势重测 AVE2
//
//  报告推翻的三条旧归因：
//    ① type 应为 1（不是 0）
//    ② 必须 IOConnectCallAsyncStructMethod（同步在 IO_Config:337 直接 0xe00002bc）
//    ③ sel 1 create 会 strncmp 版本串（大概率 "803.73.1"）
//
//  本包第一目标是【确认 0xe00002e2 的来源】：
//    · AVE2 kext 全库 0 处 movz w0,#0x2e2（我已验证）→ 不可能是 AVE2 返回
//    · 所以必须打印【原始 kern_return_t】，不经过任何名字表
//    · 同时抓 syslog 看有没有 deny(1) iokit-open-user-client AppleAVE2UserClient
//
//  做法：
//    A) 对 type 0..3 逐个 IOServiceOpen，原始码全打
//    B) 只要有一个成功，立刻试 async sel 1（0x920 字节，version @+0x28，encType @+0x918）
//    C) 再试 async sel 4（configure 0x1a0a0）—— 报告说这是 CVE 入口
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

static void L(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSString *s = [NSString stringWithUTF8String:buf];
    if (!s) return;
    NSLog(@"AVE2OPEN %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ave2open2.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
    dispatch_sync(dispatch_get_main_queue(), ^{
        [gLog appendString:line];
        if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length,0)]; }
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

// 只做参考对照，主判据是原始 hex
static const char *hint(uint32_t k)
{
    switch (k) {
        case 0:          return "KERN_SUCCESS";
        case 0xe00002b0: return "NoSuchClass?";
        case 0xe00002bc: return "kIOReturnError";
        case 0xe00002be: return "NoResources";
        case 0xe00002c0: return "NoDevice";
        case 0xe00002c1: return "NotPrivileged";
        case 0xe00002c2: return "kIOReturnBadArgument";
        case 0xe00002c5: return "ExclusiveAccess";
        case 0xe00002c7: return "kIOReturnUnsupported";
        case 0xe00002c9: return "kIOReturnInternalError";
        case 0xe00002cc: return "kIOReturnNotOpen";
        case 0xe00002d4: return "kIOReturnBusy";
        case 0xe00002d8: return "kIOReturnNotAttached";
        case 0xe00002e2: return "kIOReturnNotPermitted";
        case 0xe00002f0: return "kIOReturnNotFound";
        default:         return "?";
    }
}

static io_connect_t g_conn = MACH_PORT_NULL;
static uint32_t      g_open_type = 0xffffffff;

// A) 逐 type 试 open，打印原始码
static BOOL try_open_all_types(io_service_t svc)
{
    L("=== A) IOServiceOpen 逐 type（原始码为准）===");
    BOOL any = NO;
    for (uint32_t t = 0; t <= 3; t++) {
        io_connect_t c = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &c);
        L("  type=%u -> kr=0x%08x  (%s)  conn=0x%x",
          t, (uint32_t)kr, hint((uint32_t)kr), c);
        if (kr == KERN_SUCCESS) {
            if (!any) { g_conn = c; g_open_type = t; any = YES; }
            else { IOServiceClose(c); }
        }
        usleep(150 * 1000);
    }
    return any;
}

// B) async sel 1: create（0x920 字节，version @+0x28，encType @+0x918）
static void try_async_create(void)
{
    L("");
    L("=== B) async sel 1 (CREATE, in=0x920, version@+0x28, encType@+0x918) ===");

    uint8_t in[0x920];
    memset(in, 0, sizeof(in));
    // 版本串：报告说大概率 "803.73.1"
    const char *ver = "803.73.1";
    memcpy(in + 0x28, ver, strlen(ver) + 1);
    // encType：H.264=0 / HEVC=1，先试 0
    *(uint32_t *)(in + 0x918) = 0;

    // async 需要 wake port 与 reference
    mach_port_t wakePort = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wakePort);
    mach_port_insert_right(mach_task_self(), wakePort, wakePort, MACH_MSG_TYPE_MAKE_SEND);

    uint64_t ref = 0xA1;
    uint8_t out[0x40]; memset(out, 0, sizeof(out));
    size_t os = sizeof(out);

    kern_return_t kr = IOConnectCallAsyncStructMethod(g_conn, 1, wakePort, &ref, 1,
                                                      in, sizeof(in), out, &os);
    L("  async sel1 -> kr=0x%08x (%s)  outSize=0x%zx", (uint32_t)kr, hint((uint32_t)kr), os);
    if (os >= 16) {
        L("    out[0..3] = %08x %08x %08x %08x",
          *(uint32_t*)(out+0), *(uint32_t*)(out+4),
          *(uint32_t*)(out+8), *(uint32_t*)(out+12));
    }

    if (wakePort != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), wakePort);
    usleep(300 * 1000);
}

// 对照：同步 sel 1（报告说会在 IO_Config:337 返回 0xe00002bc）
static void try_sync_create(void)
{
    L("");
    L("=== B2) 对照：同步 sel 1（报告预期 0xe00002bc）===");
    uint8_t in[0x920];
    memset(in, 0, sizeof(in));
    const char *ver = "803.73.1";
    memcpy(in + 0x28, ver, strlen(ver) + 1);

    uint8_t out[0x40]; memset(out, 0, sizeof(out));
    size_t os = sizeof(out);
    kern_return_t kr = IOConnectCallStructMethod(g_conn, 1, in, sizeof(in), out, &os);
    L("  sync  sel1 -> kr=0x%08x (%s)  outSize=0x%zx", (uint32_t)kr, hint((uint32_t)kr), os);
    usleep(300 * 1000);
}

static void run(void)
{
    L("===== AVE2 open 重测（ave2-gate 报告方案）=====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("要点: 原始 kern_return_t + type=1 + async + 版本串 803.73.1");
    L("");

    // 试多个服务名
    const char *names[] = { "AppleAVE2Driver", "AppleAVE2", "AVEVideoEncoder", "ave2" };
    io_service_t svc = MACH_PORT_NULL;
    for (int i = 0; i < 4; i++) {
        CFMutableDictionaryRef m = IOServiceMatching(names[i]);
        io_service_t s = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
        L("[svc] %-16s -> 0x%x", names[i], s);
        if (s != MACH_PORT_NULL && svc == MACH_PORT_NULL) svc = s;
        else if (s != MACH_PORT_NULL) IOObjectRelease(s);
    }
    if (svc == MACH_PORT_NULL) { L("未匹配到服务"); SetStatus(@"未匹配"); return; }
    L("");

    if (!try_open_all_types(svc)) {
        L("");
        L("=== 结论：所有 type 都打不开 ===");
        L("  → 立刻查 syslog 有没有 deny(1) iokit-open-user-client AppleAVE2UserClient");
        L("  → 若没有 deny，说明拒绝不是 sandbox 而是别的层（需继续查）");
        SetStatus(@"全部 type 失败");
        IOObjectRelease(svc);
        return;
    }

    L("");
    L("★ type=%u 打开成功 conn=0x%x", g_open_type, g_conn);
    try_async_create();
    try_sync_create();

    L("");
    L("=== 判读 ===");
    L("  · async sel1 = KERN_SUCCESS -> ★★★ AVE2 通了，立刻做 sel4 configure");
    L("  · async sel1 = 0xe00002bc 且 sync 也是 -> 版本串或 encType 不对");
    L("  · 两者码不同 -> 证实『必须 async』这一条");

    SetStatus(@"完成，看日志");
    IOServiceClose(g_conn);
    IOObjectRelease(svc);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("ave2open2.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"ave2open2...";
    gStatus.textColor = [UIColor colorWithRed:1 green:0.5 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 84, self.window.bounds.size.width, h - 84)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
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
