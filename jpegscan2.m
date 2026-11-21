//
//  jpegscan2.m — AppleJPEGDriver 多 type 变体探测（阶段 0.7）
//
//  背景：
//    jpegscan 第一版用 type=0 打开成功（conn 拿到），但 selector 0x00~0x40 全部返回
//    kIOReturnNotAttached (0xe00002c2)。而 newUserClient 反汇编显示它做两次虚调用
//    初始化（vtable+0x360 / +0x2b0），失败才返回错误 —— 说明 client 对象是健全的，
//    NotAttached 来自分发路径上的前置状态检查。
//
//  真机已确认 type 0/1/2 都能 IOServiceOpen 成功。本工具：
//    对 type 0 / 1 / 2 分别打开一个独立 connection，
//    每个 connection 都做一遍 selector 0x00~0x20 的零参数探测，
//    对比三者的返回码差异 —— 如果某个 type 的 client 处于不同状态，
//    就能看出 NotAttached 是不是 type 相关。
//
//  安全性：与上一版完全相同，全部零参数，不传任何 buffer。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static dispatch_queue_t gQ = nil;

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "SUCCESS";
        case 0xe00002bc: return "Error";
        case 0xe00002c1: return "NotReady";
        case 0xe00002c2: return "NotAttached";
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c9: return "BadArgument";
        case 0xe00002d5: return "Busy";
        case 0xe00002d6: return "Timeout";
        case 0xe00002e2: return "NotPermitted";
        case 0xe00002e3: return "NotPrivileged";
        case 0xe00002f0: return "NotFound";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSLog(@"JPEGSCAN2 %@", s);

    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"jpegscan2.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }

    dispatch_async(gQ, ^{
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length, 0)]; }
        });
    });
}

// 对给定 connection 扫一段 selector，返回统计
static void sweep(io_connect_t conn, uint32_t baseSel, uint32_t maxSel, const char *tag)
{
    L(@"--- sweep %s (conn=0x%x) sel 0x%02x..0x%02x ---", tag, conn, baseSel, maxSel);

    int nSuccess = 0, nBadArg = 0, nUnsup = 0, nNotAtt = 0, nOther = 0;
    char firstDiff[256] = {0};

    for (uint32_t sel = baseSel; sel <= maxSel; sel++) {
        uint64_t out[8];
        memset(out, 0, sizeof(out));
        size_t outCnt = 8;
        kern_return_t r = IOConnectCallScalarMethod(conn, sel, NULL, 0, out, &outCnt);

        switch ((uint32_t)r) {
            case 0:          nSuccess++; break;
            case 0xe00002c9: nBadArg++;  break;
            case 0xe00002c7: nUnsup++;   break;
            case 0xe00002c2: nNotAtt++;  break;
            default:         nOther++;   break;
        }

        // 只打印「不是 NotAttached」的，避免刷屏；NotAttached 汇总在末尾
        if ((uint32_t)r != 0xe00002c2) {
            L(@"    sel 0x%02x -> %s (0x%08x)", sel, kr_name(r), (uint32_t)r);
            if (!firstDiff[0]) {
                snprintf(firstDiff, sizeof(firstDiff), "first non-NotAttached: 0x%02x %s", sel, kr_name(r));
            }
        }
        if (r == KERN_SUCCESS) {
            for (size_t i = 0; i < outCnt && i < 8; i++)
                L(@"        out[%zu] = 0x%016llx", i, (unsigned long long)out[i]);
        }
    }

    L(@"    summary %s: success=%d badArg=%d unsupported=%d notAttached=%d other=%d",
      tag, nSuccess, nBadArg, nUnsup, nNotAtt, nOther);
    if (firstDiff[0]) L(@"    %s", firstDiff);
}

static void run(void)
{
    L(@"===== AppleJPEGDriver multi-type probe =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());

    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) return;

    const uint32_t types[] = {0, 1, 2};
    for (int i = 0; i < 3; i++) {
        uint32_t t = types[i];
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        L(@"");
        L(@"[2.%d] IOServiceOpen(type=%u) kr=0x%08x %s conn=0x%08x",
          i, t, (uint32_t)kr, kr_name(kr), conn);
        if (kr != KERN_SUCCESS) continue;

        char tag[16];
        snprintf(tag, sizeof(tag), "t%u", t);
        sweep(conn, 0x00, 0x20, tag);

        IOServiceClose(conn);
    }

    L(@"");
    L(@"===== multi-type probe done =====");
    IOObjectRelease(svc);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("jpegscan2.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    gView.text = @"JPEG multi-type probe starting...\n";
    [vc.view addSubview:gView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { run(); }
    });
    return YES;
}
@end

int main(int argc, char *argv[])
{
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); }
}
