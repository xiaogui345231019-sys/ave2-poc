//
//  xpcprobe.m — 测 8 个高价值 Mach service 的 app 可达性
//
//  theos SDK 里没有 xpc/xpc.h，这里手写所需的最小 API 声明。
//  只做可达性判定：建连接 → 发空字典 → 等回复/错误 → 记录。
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <unistd.h>

// ---- XPC 最小声明（手写，因为 SDK 无 xpc/xpc.h）----
typedef void *xpc_object_t;
typedef void *xpc_connection_t;
typedef int   xpc_type_t;
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
extern const char *xpc_dictionary_get_string(xpc_object_t xdict, const char *key);
extern xpc_type_t xpc_get_type(xpc_object_t object);

// XPC_TYPE_* 是全局变量
extern const struct _xpc_type_s *XPC_TYPE_ERROR;
extern const struct _xpc_type_s *XPC_TYPE_DICTIONARY;
extern const char *const XPC_ERROR_KEY_DESCRIPTION;

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

typedef struct {
    const char *name;
    const char *tag;
} svc_t;

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

static void probe(const char *name, const char *tag)
{
    L("");
    L("========== %s  [%s] ==========", name, tag);
    SetStatus([NSString stringWithFormat:@"%s", tag]);

    xpc_connection_t c = xpc_connection_create_mach_service(name, NULL, 0);
    if (!c) {
        L("  create -> NULL（服务名不存在？）");
        return;
    }

    __block NSString *result = @"(timeout 4s)";
    __block BOOL gotReply = NO;

    xpc_connection_set_event_handler(c, ^(xpc_object_t event) {
        if (xpc_get_type(event) == (xpc_type_t)XPC_TYPE_ERROR) {
            const char *d = xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION);
            result = [NSString stringWithFormat:@"EVENT_ERROR: %s", d ? d : "(no desc)"];
        }
    });
    xpc_connection_resume(c);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    xpc_connection_send_message_with_reply(c, msg, dispatch_get_global_queue(0, 0), ^(xpc_object_t reply) {
        if (xpc_get_type(reply) == (xpc_type_t)XPC_TYPE_ERROR) {
            const char *d = xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION);
            result = [NSString stringWithFormat:@"REPLY_ERROR: %s", d ? d : "(no desc)"];
        } else if (xpc_get_type(reply) == (xpc_type_t)XPC_TYPE_DICTIONARY) {
            result = [NSString stringWithFormat:@"★ DICT(%zu keys)", xpc_dictionary_get_count(reply)];
        } else {
            result = [NSString stringWithFormat:@"reply type=%d", xpc_get_type(reply)];
        }
        gotReply = YES;
        dispatch_semaphore_signal(sem);
    });

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
    L("  REPLY_ERROR: Connection invalid     -> 沙箱拒绝");
    L("  REPLY_ERROR: Connection interrupted -> 服务在但连接被断");
    L("  ★ DICT(n keys)                      -> 可达且处理了空消息");
    L("  超时                                 -> 服务在但不应答");
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
