//
//  xpcprobe.m — 测 5 个高价值 Mach service 的 app 可达性
//
//  来源：kernel/userspace 契约审计（子代理 A，报告 userspace-contract-audit.md）
//    2,017 个 Mach service，1,809 个提供者不查调用方身份；
//    两端都有证据的 76 个；其中 5 个最值得验：
//      1. com.apple.Photos.CPLDiagnose.xpc   ← 唯一 _AllowedClients:["always"] + _RoleAccount:root
//      2. com.apple.commcenter.xpc           ← ent 最高（189），baseband 边界
//      3. com.apple.server.bluetooth.le.att.xpc ← 纯 raw-XPC / 99 个 xpc 导入
//      4. SpeechRecognitionCore 的 broker    ← .xpc 套 .xpc 两跳桥
//      5. com.apple.aps.mobilestoredemoport  ← demod（132 ent / 51 xpc 导入）
//
//  本包只做**可达性判定**：建连接 → 发一个空字典 → 等回复/错误 → 记录。
//  不构造畸形消息、不发数据载荷。零风险。
//
//  判读：
//    · 收到 reply          → 可达，且服务处理了空消息
//    · XPC_ERROR_CONNECTION_INVALID  → 服务存在但拒绝我们（沙箱/entitlement）
//    · XPC_ERROR_CONNECTION_INTERRUPTED → 服务存在，连接被中断（可能它要求特定握手）
//    · 超时                → 服务存在但不应答
//    · 进程崩溃            → 服务处理空消息就崩（★ 有价值）
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
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
    NSLog(@"XPCPROBE %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"xpcprobe.log"];
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

// 错误对象转字符串
static NSString *desc(xpc_object_t o)
{
    if (!o) return @"(null)";
    if (xpc_get_type(o) == XPC_TYPE_ERROR) {
        const char *d = xpc_dictionary_get_string(o, XPC_ERROR_KEY_DESCRIPTION);
        return [NSString stringWithFormat:@"ERROR: %s",
                xpc_get_type(o) == XPC_TYPE_ERROR ? (d ? d : "?") : "?"];
    }
    if (xpc_get_type(o) == XPC_TYPE_DICTIONARY) {
        return [NSString stringWithFormat:@"DICT(%zu keys)", xpc_dictionary_get_count(o)];
    }
    return [NSString stringWithFormat:@"type=%d", (int)xpc_get_type(o)];
}

typedef struct {
    const char *name;
    const char *tag;
} svc_t;

static svc_t g_svcs[] = {
    { "com.apple.Photos.CPLDiagnose.xpc",           "CPLDiagnose(always+root)" },
    { "com.apple.commcenter.xpc",                   "CommCenter(189ent)" },
    { "com.apple.server.bluetooth.le.att.xpc",      "bluetoothd-LE-ATT" },
    { "com.apple.server.bluetooth.le.att",          "bluetoothd(无.xpc后缀)" },
    { "com.apple.speech.broker",                    "SpeechBroker" },
    { "com.apple.SpeechRecognitionCore.brokerd",    "SpeechRecBroker" },
    { "com.apple.aps.mobilestoredemoport",          "demod-port" },
    { "com.apple.demod",                            "demod(无后缀)" },
};

static void probe(const char *name, const char *tag)
{
    L("");
    L("========== %s  [%s] ==========", name, tag);
    SetStatus([NSString stringWithFormat:@"%s", tag]);

    xpc_connection_t c = xpc_connection_create_mach_service(name, NULL, 0);
    if (!c) {
        L("  create -> NULL（服务名可能不存在）");
        return;
    }

    __block BOOL done = NO;
    __block NSString *result = @"(timeout)";

    xpc_connection_set_event_handler(c, ^(xpc_object_t event) {
        if (xpc_get_type(event) == XPC_TYPE_ERROR) {
            const char *d = xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION);
            result = [NSString stringWithFormat:@"EVENT_ERROR: %s", d ? d : "?"];
            done = YES;
        }
    });

    xpc_connection_resume(c);

    // 发一个空字典，等回复
    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    xpc_connection_send_message_with_reply(c, msg, dispatch_get_global_queue(0, 0), ^(xpc_object_t reply) {
        if (xpc_get_type(reply) == XPC_TYPE_ERROR) {
            const char *d = xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION);
            result = [NSString stringWithFormat:@"REPLY_ERROR: %s", d ? d : "?"];
        } else {
            result = desc(reply);
        }
        done = YES;
        dispatch_semaphore_signal(sem);
    });

    // 最多等 4 秒
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 4ULL * NSEC_PER_SEC));

    L("  结果: %s", [result UTF8String]);

    xpc_connection_cancel(c);
    usleep(200 * 1000);
}

static void run(void)
{
    L("===== XPC 可达性探测（8 个候选）=====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("只发空字典，不构造载荷。零风险。");
    L("");

    int n = sizeof(g_svcs) / sizeof(g_svcs[0]);
    for (int i = 0; i < n; i++) {
        probe(g_svcs[i].name, g_svcs[i].tag);
    }

    L("");
    L("===== 判读 =====");
    L("  · REPLY_ERROR: Connection invalid  → 沙箱拒绝（不在 profile 白名单）");
    L("  · REPLY_ERROR: Connection interrupted → 服务在，但连接被断（可能要特定握手）");
    L("  · 返回 DICT   → ★ 可达且服务处理了空消息");
    L("  · 超时        → 服务在但不应答");
    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("xpcprobe.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"xpcprobe...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 84, self.window.bounds.size.width, h - 84)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:8] ?: [UIFont systemFontOfSize:8];
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
