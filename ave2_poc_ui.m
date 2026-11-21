//
//  ave2_poc_ui.m — AppleAVE2 / CVE-2026-64747 真机 PoC（阶段 0，带 UI 外壳）
//
//  为什么重写：
//    旧版是纯控制台程序（main + printf），iOS 的 SpringBoard 拉起后没有 UIApplicationMain
//    会立即判定异常退出 → 闪退，且 printf 的输出既不在 syslog 也不在 crash log 里，看不到任何东西。
//
//  本版做法：
//    1. 最小 UIApplicationMain 外壳（保证不被杀）
//    2. 探测逻辑放在后台队列，不阻塞启动
//    3. 输出走三条通道：
//       a) NSLog("AVE2POC ...")  → pymobiledevice3 syslog live 可实时抓
//       b) 写 NSTemporaryDirectory()/ave2poc.log → pymobiledevice3 afc 可拉
//       c) 追加到屏幕上那个 UITextView → 直接看
//
//  阶段 0 只做三件事，全部只读/无副作用：
//    1. IOServiceMatching("AppleAVE2Driver") 拿 service  —— 验证沙箱 iokit-open 白名单
//    2. IOServiceOpen type 0..8 循环                      —— 确定 newUserClient 支持的 type
//    3. 打开成功后调 selector 0 的空方法                    —— 确认 user client 可用
//  不发送任何 structureInput，不触发编码/解码，不可能造成越界。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static dispatch_queue_t gLogQ = nil;

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "KERN_SUCCESS";
        case 0xe00002bc: return "kIOReturnError";
        case 0xe00002c1: return "kIOReturnNotReady";
        case 0xe00002c2: return "kIOReturnNotAttached";
        case 0xe00002c7: return "kIOReturnUnsupported";
        case 0xe00002c9: return "kIOReturnBadArgument";
        case 0xe00002d5: return "kIOReturnBusy";
        case 0xe00002d6: return "kIOReturnTimeout";
        case 0xe00002e2: return "kIOReturnNotPermitted";
        case 0xe00002e3: return "kIOReturnNotPrivileged";
        case 0xe00002f0: return "kIOReturnNotFound";
        case 0xe00003e9: return "AVE2_PRIVATE_FAIL(0xe00003e9)";
        default:         return "?";
    }
}

// 三通道输出
static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    NSLog(@"AVE2POC %@", s);                       // 通道 a: syslog

    NSString *line = [s stringByAppendingString:@"\n"];
    FILE *f = fopen([[[NSTemporaryDirectory() stringByAppendingPathComponent:@"ave2poc.log"] description] UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }   // 通道 b: 文件

    dispatch_async(gLogQ, ^{                        // 通道 c: 屏幕
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) {
                gView.text = gLog;
                NSRange r = NSMakeRange(gLog.length, 0);
                [gView scrollRangeToVisible:r];
            }
        });
    });
}

static void dump_props(io_registry_entry_t entry)
{
    CFMutableDictionaryRef props = NULL;
    kern_return_t kr = IORegistryEntryCreateCFProperties(entry, &props, kCFAllocatorDefault, 0);
    if (kr != KERN_SUCCESS || props == NULL) {
        L(@"[props] create failed kr=0x%08x", (uint32_t)kr);
        return;
    }
    CFIndex n = CFDictionaryGetCount(props);
    L(@"[props] %ld keys", (long)n);
    const void **keys = (const void **)malloc(sizeof(void *) * (size_t)n);
    const void **vals = (const void **)malloc(sizeof(void *) * (size_t)n);
    if (keys && vals) {
        CFDictionaryGetKeysAndValues(props, keys, vals);
        for (CFIndex i = 0; i < n; i++) {
            char kbuf[96] = {0}, vbuf[256] = {0};
            if (CFGetTypeID(keys[i]) == CFStringGetTypeID())
                CFStringGetCString((CFStringRef)keys[i], kbuf, sizeof(kbuf), kCFStringEncodingUTF8);
            CFStringRef vs = CFCopyDescription(vals[i]);
            if (vs) { CFStringGetCString(vs, vbuf, sizeof(vbuf), kCFStringEncodingUTF8); CFRelease(vs); }
            L(@"  %-28s = %s", kbuf, vbuf);
        }
    }
    free(keys); free(vals);
    CFRelease(props);
}

static void run_probe(void)
{
    L(@"===== AVE2 PoC stage0 start =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());
    L(@"tmp=%@", NSTemporaryDirectory());

    // ---------- [1] match ----------
    L(@"[1] IOServiceMatching(\"AppleAVE2Driver\")");
    CFMutableDictionaryRef match = IOServiceMatching("AppleAVE2Driver");
    if (!match) { L(@"    FAILED: matching returned NULL"); return; }
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, match);
    L(@"    service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) {
        L(@"    FAILED: no matching service");
        L(@"    => sandbox iokit-open whitelist does NOT cover AppleAVE2Driver");
        return;
    }
    dump_props(svc);

    // ---------- [2] type sweep ----------
    L(@"[2] IOServiceOpen type sweep 0..8");
    io_connect_t good = MACH_PORT_NULL;
    uint32_t goodType = 0xFFFFFFFF;
    for (uint32_t t = 0; t <= 8; t++) {
        io_connect_t conn = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), t, &conn);
        L(@"  type=%u  kr=0x%08x  %s", t, (uint32_t)kr, kr_name(kr));
        if (kr == KERN_SUCCESS) {
            L(@"    >>> OPEN OK  type=%u conn=0x%08x", t, conn);
            if (good == MACH_PORT_NULL) { good = conn; goodType = t; }
            else IOServiceClose(conn);
        }
    }

    if (good == MACH_PORT_NULL) {
        L(@"[2] result: no type opened");
        IOObjectRelease(svc);
        L(@"===== stage0 end (blocked at IOServiceOpen) =====");
        return;
    }
    L(@"[2] result: good_type=%u", goodType);

    // ---------- [3] harmless selector ----------
    L(@"[3] IOConnectCallScalarMethod(selector=0)");
    uint64_t out[16]; memset(out, 0, sizeof(out)); size_t outCnt = 16;
    kern_return_t kr = IOConnectCallScalarMethod(good, 0, NULL, 0, out, &outCnt);
    L(@"    kr=0x%08x %s  outCnt=%zu", (uint32_t)kr, kr_name(kr), outCnt);
    for (size_t i = 0; i < outCnt && i < 16; i++)
        L(@"      out[%zu] = 0x%016llx", i, (unsigned long long)out[i]);

    IOServiceClose(good);
    IOObjectRelease(svc);
    L(@"===== AVE2 PoC stage0 done (good_type=%u) =====", goodType);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gLogQ) gLogQ = dispatch_queue_create("ave2poc.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];

    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:10] ?: [UIFont systemFontOfSize:10];
    gView.editable = NO;
    gView.text = @"AVE2 PoC starting...\n";
    [vc.view addSubview:gView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool { run_probe(); }
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
