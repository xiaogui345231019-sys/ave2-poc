//
//  xpcprobe.m v3 — 修两个判定 bug
//
//  v2 的两个问题：
//    1) dlsym 在 libSystem.B.dylib 里查 XPC_TYPE_ERROR / XPC_TYPE_DICTIONARY -> 0x0
//       （实际在 libsystem_xpc.dylib）
//    2) xpc_get_type 返回的是指针，强转 int 被截断 -> 8 个服务显示同一个值
//
//  v3 修法：
//    · 符号改用 dlsym(RTLD_DEFAULT, ...) 查（覆盖所有已加载库）
//    · 主判据改成 XPCErrorDescription 键（XPC_ERROR_KEY_DESCRIPTION 的字面值）
//      - 有值 -> 是 error，打印 desc
//      - 没值 -> 是非错误回复，打印 key 数
//    · 顺带记录**响应时间**：Connection invalid 通常立刻返回，真服务有处理延迟
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <unistd.h>

typedef void *xpc_object_t;
typedef void *xpc_connection_t;
typedef void (^xpc_handler_t)(xpc_object_t);

extern xpc_connection_t xpc_connection_create_mach_service(const char *name,
                                                           dispatch_queue_t targetq,
                                                           uint64_t flags);
extern void xpc_connection_set_event_handler(xpc_connection_t connection, xpc_handler_t handler);
extern void xpc_connection_resume(xpc_connection_t connection);
extern void xpc_connection_cancel(xpc_connection_t connection);
extern void xpc_connection_send_message_with_reply(xpc_connection_t connection,
                                                    xpc_object_t message,
                                                    dispatch_queue_t replyq,
                                                    xpc_handler_t handler);
extern xpc_object_t xpc_dictionary_create(const void *keys, const void *values, size_t count);
extern size_t xpc_dictionary_get_count(xpc_object_t xdict);

typedef const char *(*fn_dict_string_t)(xpc_object_t, const char *);
static fn_dict_string_t p_dict_string = NULL;

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

typedef struct { const char *name; const char *tag; } svc_t;

static svc_t g_svcs[] = {
    { "com.apple.Photos.CPLDiagnose.xpc",        "CPLDiagnose(always+root)" },
    { "com.apple.commcenter.xpc",                "CommCenter(189ent)" },
    { "com.apple.server.bluetooth.le.att.xpc",   "bt-LE-ATT(.xpc)" },
    { "com.apple.server.bluetooth.le.att",       "bt-LE-ATT(noext)" },
    { "com.apple.speech.broker",                 "SpeechBroker" },
    { "com.apple.SpeechRecognitionCore.brokerd", "SpeechRecBroker" },
    { "com.apple.aps.mobilestoredemoport",       "demod-port" },
    { "com.apple.demod",                         "demod" },
};

static double g_tb_numer = 1, g_tb_denom = 1;

// 判据：先看有没有 XPCErrorDescription，再看 key 数
static NSString *classify(xpc_object_t o, double ms)
{
    if (!o) return [NSString stringWithFormat:@"(null) [%.1fms]", ms];

    const char *d = p_dict_string ? p_dict_string(o, "XPCErrorDescription") : NULL;
    if (d) {
        // 是 error
        NSString *ds = [NSString stringWithUTF8String:d];
        if (!ds) ds = @"(bad utf8)";
        return [NSString stringWithFormat:@"ERROR [%.1fms]: %@", ms, ds];
    }
    // 非 error：当 dict 处理
    size_t n = xpc_dictionary_get_count(o);
    return [NSString stringWithFormat:@"★ NON-ERROR [%.1fms] keys=%zu", ms, n];
}

static void probe(const char *name, const char *tag)
{
    L("");
    L("========== %s  [%s] ==========", name, tag);
    SetStatus([NSString stringWithFormat:@"%s", tag]);

    xpc_connection_t c = xpc_connection_create_mach_service(name, NULL, 0);
    if (!c) { L("  create -> NULL（服务名不存在？）"); return; }

    __block NSString *result = @"(timeout 4s)";

    xpc_connection_set_event_handler(c, ^(xpc_object_t event) {
        result = [NSString stringWithFormat:@"async(no reply yet): %@", classify(event, -1)];
    });
    xpc_connection_resume(c);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    uint64_t t0 = mach_absolute_time();
    xpc_connection_send_message_with_reply(c, msg, dispatch_get_global_queue(0, 0), ^(xpc_object_t reply) {
        uint64_t t1 = mach_absolute_time();
        double ms = (double)(t1 - t0) * g_tb_numer / g_tb_denom / 1000000.0;
        result = [NSString stringWithFormat:@"reply: %@", classify(reply, ms)];
        dispatch_semaphore_signal(sem);
    });

    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 4ULL * NSEC_PER_SEC));
    L("  %s", [result UTF8String]);

    xpc_connection_cancel(c);
    usleep(200 * 1000);
}

static void run(void)
{
    L("===== XPC 可达性探测 v3（8 个候选）=====");
    L("uid=%d pid=%d", getuid(), getpid());

    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    g_tb_numer = tb.numer; g_tb_denom = tb.denom;

    // RTLD_DEFAULT 查所有已加载库
    p_dict_string = (fn_dict_string_t)dlsym(RTLD_DEFAULT, "xpc_dictionary_get_string");
    if (!p_dict_string) {
        void *h = dlopen("/usr/lib/libsystem_xpc.dylib", RTLD_LAZY);
        p_dict_string = (fn_dict_string_t)dlsym(h, "xpc_dictionary_get_string");
    }
    L("[dlsym] dict_get_string = %p", p_dict_string);
    if (!p_dict_string) { L("符号解析失败，无法判定"); SetStatus(@"dlsym 失败"); return; }
    L("");

    int n = sizeof(g_svcs) / sizeof(g_svcs[0]);
    for (int i = 0; i < n; i++) probe(g_svcs[i].name, g_svcs[i].tag);

    L("");
    L("===== 判读 =====");
    L("  ERROR [<1ms]: Connection invalid      -> 沙箱拒绝（立刻返回）");
    L("  ERROR [>1ms]: Connection interrupted  -> 服务在但连接被断（有处理延迟）");
    L("  ★ NON-ERROR                            -> 可达且服务处理了空消息");
    L("  超时 4s                                 -> 服务在但不应答");
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
    gStatus.text = @"xpcprobe v3...";
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
