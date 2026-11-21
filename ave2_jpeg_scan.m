//
//  ave2_jpeg_scan.m — AppleJPEGDriver selector 面动态枚举（阶段 0.6）
//
//  背景：
//    真机实测 AppleJPEGDriver 的 IOServiceOpen 完全放行（t0/t1/t2 全 OK），
//    而 AppleAVE2Driver 被沙箱 mac_iokit_check_open_service 挡住。
//    离线想解 IOExternalMethodDispatch 表，但该 kext 的表指针是 PAC 签名形态，
//    静态解不出来（__DATA_CONST/__DATA 都扫过 0 命中）。
//
//  本工具：直接对 selector 0..0x40 逐个发一个「零输入」的 scalar 调用，记录返回码。
//
//  安全性：
//    所有调用都传 scalarInputCount = 0、structureInput = NULL、structureOutput = NULL。
//    任何真正要读参数的处理函数都会返回 kIOReturnBadArgument；
//    不会触发解码/编码（缺 buffer），也不会造成越界。
//
//  判读方式：
//    kIOReturnUnsupported  -> 该 selector 不存在（分发表范围外或空槽）
//    kIOReturnBadArgument  -> selector 存在，但缺参数（正常，说明入口有效）
//    kIOReturnNotPermitted -> selector 存在但需要权限
//    KERN_SUCCESS          -> 存在且无需参数就能跑通（最有意思）
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

    NSLog(@"JPEGSCAN %@", s);

    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"jpegscan.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }

    dispatch_async(gQ, ^{
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) {
                gView.text = gLog;
                [gView scrollRangeToVisible:NSMakeRange(gLog.length, 0)];
            }
        });
    });
}

static void run_jpeg_scan(void)
{
    L(@"===== AppleJPEGDriver selector enumeration =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());

    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    if (!m) { L(@"[1] matching NULL"); return; }
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) { L(@"[1] FAILED no service"); return; }

    // 真机已确认 t0/t1/t2 都能开，这里固定用 0
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    L(@"[2] IOServiceOpen(type=0) kr=0x%08x %s conn=0x%08x",
      (uint32_t)kr, kr_name(kr), conn);
    if (kr != KERN_SUCCESS) { IOObjectRelease(svc); return; }

    L(@"");
    L(@"%-6s  %-14s  %s", "SEL", "RESULT", "NOTE");
    L(@"------------------------------------------------");

    int nSuccess = 0, nBadArg = 0, nUnsupported = 0, nOther = 0;

    for (uint32_t sel = 0; sel <= 0x40; sel++) {
        uint64_t out[8];
        memset(out, 0, sizeof(out));
        size_t outCnt = 8;

        kern_return_t r = IOConnectCallScalarMethod(conn, sel, NULL, 0, out, &outCnt);

        const char *note = "";
        if (r == KERN_SUCCESS)                       { note = "<<< EXISTS, no-arg OK"; nSuccess++; }
        else if ((uint32_t)r == 0xe00002c9)          { note = "exists, needs args";      nBadArg++; }
        else if ((uint32_t)r == 0xe00002c7)          { note = "no such selector";        nUnsupported++; }
        else                                         { note = "";                        nOther++; }

        L(@"0x%02x    %-14s  %s", sel, kr_name(r), note);

        // 若恰好无参成功，把返回值也打出来
        if (r == KERN_SUCCESS) {
            for (size_t i = 0; i < outCnt && i < 8; i++)
                L(@"           out[%zu] = 0x%016llx", i, (unsigned long long)out[i]);
        }
    }

    L(@"------------------------------------------------");
    L(@"summary: success=%d badArg=%d unsupported=%d other=%d",
      nSuccess, nBadArg, nUnsupported, nOther);
    L(@"===== jpeg scan done =====");

    IOServiceClose(conn);
    IOObjectRelease(svc);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("jpegscan.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    gView.text = @"JPEG selector scan starting...\n";
    [vc.view addSubview:gView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { run_jpeg_scan(); }
    });
    return YES;
}

@end

int main(int argc, char *argv[])
{
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
