//
//  typecast2.m — 对全部 IORegistry 服务批量扩 type（0..15）
//
//  起因（iorenum 的结果）：
//    1129 个实例 / 203 个 IOClass 里，
//      只有 5 个在 type 0 就能开：AppleKeyStore / IOSurfaceRoot / M2ScalerCSC / JPEG / AppleCLCD2
//      113 个 type 0 返回 Unsupported  ← **沙箱放行，只是 type 0 没实现**
//      36 个 NotPermitted（真拒绝）
//      49 个其他（BadArgument 等 = type 0 有实现但参数/条件不对）
//
//  之前只对 3 个（H13Camera/AVD/SPU）扩到 type 15，另外 110 个一个都没扩过。
//  本包对**全部 203 个 IOClass** 都跑 type 0..15，把所有能成功的 (class, type) 抓出来。
//
//  安全性：只 open/close，不调任何 selector。零风险，可能耗时几十秒。
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
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"typecast2.log"];
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
    CFStringRef k = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    CFTypeRef v = IORegistryEntryCreateCFProperty(obj, k, kCFAllocatorDefault, 0);
    if (!v) return nil;
    NSString *s = nil;
    if (CFGetTypeID(v) == CFStringGetTypeID()) s = (__bridge_transfer NSString *)v;
    else CFRelease(v);
    return s;
}

// 每个能成功的 (class, type)
typedef struct {
    char cls[64];
    int  types[16];
    int  ntypes;
    int  t0rc;          // type 0 的返回码（区分 Unsupported / BadArgument / NotPermitted）
} hit_t;

static hit_t g_hit[64]; int g_nhit = 0;

static void note(NSString *cls, int type, int t0rc)
{
    const char *nm = [cls UTF8String];
    for (int i = 0; i < g_nhit; i++) {
        if (strcmp(g_hit[i].cls, nm) == 0) {
            if (g_hit[i].ntypes < 16) g_hit[i].types[g_hit[i].ntypes++] = type;
            return;
        }
    }
    if (g_nhit >= 64) return;
    hit_t *h = &g_hit[g_nhit++];
    strncpy(h->cls, nm, sizeof(h->cls)-1);
    h->cls[sizeof(h->cls)-1] = 0;
    h->types[0] = type;
    h->ntypes = 1;
    h->t0rc = t0rc;
}

static void run(void)
{
    L(@"===== 全量 IORegistry × type 0..15 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    CFMutableDictionaryRef m = IOServiceMatching("IOService");
    io_iterator_t iter = 0;
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter) != KERN_SUCCESS) {
        L(@"枚举失败"); return;
    }

    io_object_t svc;
    NSMutableSet *seen = [NSMutableSet set];
    NSMutableArray *classes = [NSMutableArray array];
    NSMutableDictionary *t0rcMap = [NSMutableDictionary dictionary];

    // 第一遍：收集所有 unique IOClass + type0 返回码
    while ((svc = IOIteratorNext(iter))) {
        NSString *cls = prop_str(svc, "IOClass");
        if (!cls) cls = @"(null)";
        if (![seen containsObject:cls]) {
            [seen addObject:cls];
            [classes addObject:cls];

            io_connect_t c = MACH_PORT_NULL;
            kern_return_t r = IOServiceOpen(svc, mach_task_self(), 0, &c);
            if (r == KERN_SUCCESS) IOServiceClose(c);
            t0rcMap[cls] = @((int)r);
        }
        IOObjectRelease(svc);
    }
    IOObjectRelease(iter);
    L(@"unique IOClass: %d 个", (int)classes.count);

    // 第二遍：对每个 class 的实例，跑 type 0..15
    NSMutableDictionary *byName = [NSMutableDictionary dictionary];
    m = IOServiceMatching("IOService");
    if (IOServiceGetMatchingServices(kIOMainPortDefault, m, &iter) != KERN_SUCCESS) return;

    int processed = 0;
    while ((svc = IOIteratorNext(iter))) {
        NSString *cls = prop_str(svc, "IOClass");
        if (!cls) cls = @"(null)";
        // 每个 class 只取第一个实例
        if (byName[cls]) { IOObjectRelease(svc); continue; }
        byName[cls] = @(1);
        processed++;

        int t0 = [t0rcMap[cls] intValue];
        BOOL anyHit = (t0 == 0);

        // type 0 已经成功的话不用再扫，直接记
        if (anyHit) {
            note(cls, 0, t0);
        } else {
            // type 1..15
            for (uint32_t t = 1; t <= 15; t++) {
                io_connect_t c = MACH_PORT_NULL;
                kern_return_t r = IOServiceOpen(svc, mach_task_self(), t, &c);
                if (r == KERN_SUCCESS) {
                    IOServiceClose(c);
                    note(cls, (int)t, t0);
                    anyHit = YES;
                    L(@"  ★ %-42s type=%-2u 成功（type0 是 %s）", [cls UTF8String], t, kr_name(t0));
                }
            }
        }

        IOObjectRelease(svc);
        if (processed % 20 == 0) {
            SetStatus([NSString stringWithFormat:@"%d/%d", processed, (int)classes.count]);
        }
    }
    IOObjectRelease(iter);

    // 汇总
    L(@"");
    L(@"===== 汇总：能打开的服务 =====");
    for (int i = 0; i < g_nhit; i++) {
        char tb[64] = {0}; int o = 0;
        for (int k = 0; k < g_hit[i].ntypes && o < 60; k++)
            o += snprintf(tb+o, 60-o, "%s%d", k?"/":"", g_hit[i].types[k]);
        L(@"  %-42s types=[%-12s]  (type0=%s)", g_hit[i].cls, tb, kr_name(g_hit[i].t0rc));
    }
    L(@"");
    L(@"  共 %d 个服务能打开", g_nhit);

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
    if (!gQ) gQ = dispatch_queue_create("typecast2.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"typecast2...";
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
