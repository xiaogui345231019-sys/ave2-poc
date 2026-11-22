//
//  xpcprobe.m — 测 8 个高价值 Mach service 的 app 可达性（v2）
//
//  v1 的两个构建问题：
//    1) theos SDK 没有 xpc/xpc.h        -> 手写函数声明
//    2) XPC_TYPE_ERROR / XPC_TYPE_DICTIONARY / XPC_ERROR_KEY_DESCRIPTION 是数据符号，
//       链接找不到（它们在 libsystem_xpc.dylib 里）-> 改用 dlsym 运行时查
//

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach/mach.h>
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

// 运行时查的符号
typedef int (*fn_xpc_get_type_t)(xpc_object_t);
typedef const char *(*fn_xpc_dict_get_string_t)(xpc_object_t, const char *);
typedef const char *(*fn_xpc_copy_description_t)(xpc_object_t);

static fn_xpc_get_type_t         p_get_type    = NULL;
static fn_xpc_dict_get_string_t  p_dict_string = NULL;
static const void               *g_type_error  = NULL;
static const void               *g_type_dict   = NULL;
static const char *const        *g_errkey_desc = NULL;

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

// 判断一个 xpc_object 是不是 error / dict，返回描述
static NSString *classify(xpc_object_t o)
{
    if (!o) return @"(null object)";
    int t = p_get_type ? p_get_type(o) : -1;
    int te = (int)(long)g_type_error;
    int td = (int)(long)g_type_dict;
    if (g_type_error && t == te) {
        const char *d = p_dict_string ? p_dict_string(o, "XPCErrorDescription") : NULL;
        return [NSString stringWithFormat:@"ERROR: %s", d ? d : "(no desc)"];
    }
    if (g_type_dict && t == td) {
        return [NSString stringWithFormat:@"★ DICT(%zu keys)", xpc_dictionary_get_count(o)];
    }
    return [NSString stringWithFormat:@"other type=%d", t];
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
        result = [NSString stringWithFormat:@"async: %@", classify(event)];
    });
    xpc_connection_resume(c);

    xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    xpc_connection_send_message_with_reply(c, msg, dispatch_get_global_queue(0, 0), ^(xpc_object_t reply) {
        result = [NSString stringWithFormat:@"reply: %@", classify(reply)];
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

    // 运行时解析 XPC 的数据符号
    void *h = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
    if (!h) h = dlopen(NULL, RTLD_LAZY);
    p_get_type    = (fn_xpc_get_type_t)dlsym(h, "xpc_get_type");
    p_dict_string = (fn_xpc_dict_get_string_t)dlsym(h, "xpc_dictionary_get_string");
    g_type_error  = dlsym(h, "XPC_TYPE_ERROR");
    g_type_dict   = dlsym(h, "XPC_TYPE_DICTIONARY");
    L("[dlsym] get_type=%p dict_string=%p TYPE_ERROR=%p TYPE_DICT=%p",
      p_get_type, p_dict_string, g_type_error, g_type_dict);
    if (!p_get_type || !g_type_error) {
        L("XPC 符号解析失败，退化为只看有没有回复");
    }
    L("");

    int n = sizeof(g_svcs) / sizeof(g_svcs[0]);
    for (int i = 0; i < n; i++) probe(g_svcs[i].name, g_svcs[i].tag);

    L("");
    L("===== 判读 =====");
    L("  ERROR: Connection invalid     -> 沙箱拒绝");
    L("  ERROR: Connection interrupted -> 服务在但连接被断");
    L("  ★ DICT(n keys)                 -> 可达且处理了空消息");
    L("  超时                          -> 服务在但不应答");
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
