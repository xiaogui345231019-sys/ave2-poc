//
//  iorenum.m — 全量枚举 IORegistry 里所有 IOService，逐个尝试 open
//
//  之前的做法（kextscan）是「猜名字 + 逐个测」——只测了 23 个已知的，
//  而且名字对了才有效（AppleJPEGDecodeDriver / AppleProResDecoder / IOGPUDevice
//  这些根本匹配不到）。换打法：**不猜，全量枚举**。
//
//  做法：
//    1. IOServiceMatching("IOService") 拿全部 IOService 实例（几百个）
//    2. 对每个读 IOClass / CFBundleIdentifier / IOProviderClass
//    3. 尝试 IOServiceOpen(type 0)，记录返回码
//    4. 筛出「能打开」的，和「NotPermitted / Unsupported」的分开
//
//  判读：
//    · SUCCESS            ⇒ 沙箱放行，是一个入口（不管之前认不认识它）
//    · Unsupported        ⇒ 沙箱放行但该 type 无实现在 newUserClient（也可扩 type）
//    · NotPermitted       ⇒ 沙箱拒绝（不在白名单）
//    · 其他               ⇒ 记下来，看是什么
//
//  安全性：只 open/close，不调任何 selector。零风险。
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
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"iorenum.log"];
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

static NSString *prop_str(io_object_t obj, const char *key)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(obj, CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8), kCFAllocatorDefault, 0);
    if (!v) return nil;
    NSString *s = nil;
    if (CFGetTypeID(v) == CFStringGetTypeID()) {
        s = (__bridge_transfer NSString *)v;
    } else {
        CFRelease(v);
    }
    return s;
}

typedef struct {
    char cls[64];
    int  st0;
} rec_t;

static rec_t g_ok[512];    int g_nok = 0;
static rec_t g_unsup[512]; int g_nunsup = 0;
static rec_t g_denied[256];int g_ndenied = 0;
static rec_t g_other[256]; int g_nother = 0;

static void run(void)
{
    L(@"===== IORegistry 全量枚举 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    CFMutableDictionaryRef m = IOServiceMatching("IOService");
    io_iterator_t iter = 0;
    kern_return_t kr = IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter);
    if (kr != KERN_SUCCESS) { L(@"IOServiceGetMatchingServices -> 0x%x", kr); return; }

    io_object_t svc;
    int total = 0, tested = 0;
    NSMutableSet *seenClass = [NSMutableSet set];

    while ((svc = IOIteratorNext(iter))) {
        total++;
        NSString *cls = prop_str(svc, "IOClass");
        if (!cls) cls = @"(null)";

        // 同一 IOClass 只测第一次（避免对几十个相同实例重复 open）
        if ([seenClass containsObject:cls]) {
            IOObjectRelease(svc);
            continue;
        }
        [seenClass addObject:cls];
        tested++;

        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t r = IOServiceOpen(svc, mach_task_self(), 0, &conn);
        if (r == KERN_SUCCESS) IOServiceClose(conn);

        const char *nm = [cls UTF8String];
        rec_t rec;
        strncpy(rec.cls, nm, sizeof(rec.cls)-1);
        rec.cls[sizeof(rec.cls)-1] = 0;
        rec.st0 = (int)r;

        if (r == KERN_SUCCESS) {
            if (g_nok < 512) g_ok[g_nok++] = rec;
            L(@"  [OPEN] %-42s", nm);
        } else if ((uint32_t)r == 0xe00002c7) {
            if (g_nunsup < 512) g_unsup[g_nunsup++] = rec;
        } else if ((uint32_t)r == 0xe00002e2) {
            if (g_ndenied < 256) g_denied[g_ndenied++] = rec;
        } else {
            if (g_nother < 256) g_other[g_nother++] = rec;
        }

        IOObjectRelease(svc);
        if (tested % 40 == 0) {
            SetStatus([NSString stringWithFormat:@"已测 %d/%d", tested, total]);
        }
    }
    IOObjectRelease(iter);

    L(@"");
    L(@"===== 汇总（共 %d 个实例，%d 个不同 IOClass 被测）=====", total, tested);

    L(@"");
    L(@"★★★ [能打开 SUCCESS]  %d 个", g_nok);
    for (int i = 0; i < g_nok; i++) L(@"    %s", g_ok[i].cls);

    L(@"");
    L(@"[Unsupported — 沙箱放行但 type0 无实现]  %d 个", g_nunsup);
    for (int i = 0; i < g_nunsup && i < 120; i++) L(@"    %s", g_unsup[i].cls);
    if (g_nunsup > 120) L(@"    ...（还有 %d 个）", g_nunsup - 120);

    L(@"");
    L(@"[NotPermitted — 沙箱拒绝]  %d 个", g_ndenied);
    for (int i = 0; i < g_ndenied && i < 60; i++) L(@"    %s", g_denied[i].cls);
    if (g_ndenied > 60) L(@"    ...（还有 %d 个）", g_ndenied - 60);

    L(@"");
    L(@"[其他返回码]  %d 个", g_nother);
    for (int i = 0; i < g_nother && i < 40; i++)
        L(@"    %-42s 0x%08x %s", g_other[i].cls, g_other[i].st0, kr_name(g_other[i].st0));

    SetStatus(@"完成，看日志");
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
    if (!gQ) gQ = dispatch_queue_create("iorenum.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"iorenum...";
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
