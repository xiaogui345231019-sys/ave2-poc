//
//  ave2_scan.m — IOKit 沙箱可达性扫描（阶段 0.5）
//
//  背景：
//    AVE2 PoC 在真机实测发现 IOServiceOpen 全部返回 kIOReturnNotPermitted (0xe00002e2)。
//    xnu 源码定位到拦截点是 is_io_service_open_extended() 里的：
//        if (mac_iokit_check_open_service(kauth_cred_get(), service, connect_type) != 0)
//            return kIOReturnNotPermitted;
//    这是沙箱 MACF 的 iokit-open 白名单，按 IOClass 逐个列。
//
//  本工具目的：把白名单摸清楚——对一批高价值 service，分别测
//      getMatching（拿到对象） 和 IOServiceOpen（拿连接，type 0..3）
//  输出一张表，作为 A 段下一步"从哪个入口下手"的依据。
//
//  安全性：只做匹配与打开，不发送任何结构体，不调用任何 selector（type 打开成功才 close）。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

// 候选 service / IOClass 清单：目标 + 沙箱常见放行项 + 已知有 user client 的驱动
static const char *kCandidates[] = {
    // —— 我们的目标 ——
    "AppleAVE2Driver",
    // —— 图形栈 ——
    "IOSurfaceRoot",
    "IOSurfaceRootUserClient",
    "AGXDeviceUserClient",
    "AppleCLCD",
    "AppleDCP",
    "IOMobileFramebuffer",
    // —— HID / 输入 ——
    "IOHIDSystem",
    "IOHIDEventSystemUserClient",
    "IOHIDEventDriver",
    // —— 蓝牙 / 无线 ——
    "AppleH1CLinkUserClient",
    "AppleBluetoothModule",
    // —— 平台 / 系统 ——
    "IOPlatformExpertDevice",
    "IOResources",
    "AppleSMC",
    "AppleSEPManager",
    "AppleMobileFileIntegrity",
    // —— 其他驱动 ——
    "AppleJPEGDriver",
    "IOSerialBSDClient",
    "AppleMultitouchDevice",
    "AppleM68Touchscreen",
    "IOAESAccelerator",
    "AppleARMPMU",
    NULL
};

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

    NSLog(@"AVE2SCAN %@", s);

    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *logPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ave2scan.log"];
    FILE *f = fopen([logPath UTF8String], "a");
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

static void scan_one(const char *cls)
{
    CFMutableDictionaryRef m = IOServiceMatching(cls);
    if (!m) { L(@"%-30s  match=NULL", cls); return; }

    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    if (svc == MACH_PORT_NULL) {
        L(@"%-30s  get=NULL", cls);
        return;
    }

    // 记录它真实的 IOClass（有些名字匹配到的是别的类）
    char realClass[128] = {0};
    {
        CFMutableDictionaryRef props = NULL;
        if (IORegistryEntryCreateCFProperties(svc, &props, kCFAllocatorDefault, 0) == KERN_SUCCESS && props) {
            CFTypeRef v = CFDictionaryGetValue(props, CFSTR("IOClass"));
            if (v && CFGetTypeID(v) == CFStringGetTypeID())
                CFStringGetCString((CFStringRef)v, realClass, sizeof(realClass), kCFStringEncodingUTF8);
            CFRelease(props);
        }
    }

    char results[256] = {0};
    io_connect_t good = MACH_PORT_NULL;
    uint32_t goodType = 0xFFFFFFFF;

    for (uint32_t t = 0; t <= 3; t++) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        char buf[64];
        snprintf(buf, sizeof(buf), " t%u=%s", t, kr == KERN_SUCCESS ? "OK" : kr_name(kr));
        strlcat(results, buf, sizeof(results));
        if (kr == KERN_SUCCESS) {
            if (good == MACH_PORT_NULL) { good = conn; goodType = t; }
            else IOServiceClose(conn);
        }
    }

    L(@"%-30s  get=OK[%s]%s%s", cls, realClass[0] ? realClass : "?",
      results, good != MACH_PORT_NULL ? "   <<< OPENABLE" : "");

    if (good != MACH_PORT_NULL) IOServiceClose(good);
    IOObjectRelease(svc);
}

static void run_scan(void)
{
    L(@"===== IOKit sandbox reachability scan =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());
    L(@"");
    L(@"%-30s  %s", "CLASS", "RESULT");
    L(@"----------------------------------------------");

    for (int i = 0; kCandidates[i]; i++) {
        @autoreleasepool { scan_one(kCandidates[i]); }
    }

    L(@"----------------------------------------------");
    L(@"===== scan done =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("ave2scan.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];

    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    gView.text = @"IOKit scan starting...\n";
    [vc.view addSubview:gView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { run_scan(); }
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
