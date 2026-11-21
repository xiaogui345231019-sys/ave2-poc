//
//  jpeg_probe3.m — 按公开 PoC 的方式调用 AppleJPEGDriver（结构体版）
//
//  起因（关键认知修正）：
//    之前的 jpegscan / jpegscan2 用的是 IOConnectCallScalarMethod(conn, sel, NULL, 0, ...)
//    即 structureInputSize = 0。而公开 PoC（0xjohnnydev/CVE-2026-20687-AppleJPEGDriver-UAF）
//    用的是 IOConnectCallStructMethod(conn, 1, &input, 0x58, &output, &outSize)。
//
//    若 selector 1 的 checkStructureInputSize == 0x58，则"传 0"必然对不上，
//    很可能就返回我们现在看到的 kIOReturnNotAttached —— 也就是说 NotAttached
//    可能根本不是权限/状态问题，而是"参数尺寸不匹配"。
//
//  公开 PoC 给出的表（IOUserClient2022，10 项 × 40 字节）：
//    Sel 0: getTarget      - 无参
//    Sel 1: decode         - structIn=0x58  structOut=0x58
//    Sel 2: query          - 无参
//    Sel 3: encode         - structIn=0x58  structOut=0x58
//    Sel 4/5: ???          - structIn=0x1000 structOut=0x1000
//    Sel 6/7: async de/enc - structIn=0xDA0 allowAsync=1
//    Sel 8/9: privileged
//
//  本包要回答：
//    A. 用正确尺寸（0x58）调 selector 1，返回码是什么？（对比 scalar 版的全 NotAttached）
//    B. selector 0 / 2 用"无参"调用（PoC 的写法）返回什么？
//    C. selector 10（超出 10 项表）返回什么？—— 用来判断表长到底是 10 还是更多
//    D. 用 0x58 全零结构体调 decode，是否进入真正的 decode 路径
//
//  安全性：只提交解码请求，不关闭连接、不制造 UAF、不 spray。
//  最坏情况是解码失败返回错误码。
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
        case 0xe00002cd: return "ExclusiveAccess";
        case 0xe00002d5: return "Busy";
        case 0xe00002d6: return "Timeout";
        case 0xe00002e2: return "NotPermitted";
        case 0xe00002e3: return "NotPrivileged";
        case 0xe00002f0: return "NotFound";
        case 0xe00002eb: return "InsufficientMemory";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"JPEGP3 %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"jpegp3.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
    dispatch_async(gQ, ^{
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length, 0)]; }
        });
    });
}

// 公开 PoC 的 AppleJPEGDriverIOStruct（0x58 = 88 字节）
typedef struct __attribute__((packed)) {
    uint32_t sourceID;       // +0x00 源 IOSurface ID
    uint32_t field_04;       // +0x04 JPEG 输入大小
    uint32_t destID;         // +0x08 目标 IOSurface ID
    uint32_t field_0C;       // +0x0C 输出缓冲大小
    uint32_t field_10;       // +0x10 未知
    uint32_t width;          // +0x14
    uint32_t height;         // +0x18
    uint32_t field_1C;       // +0x1C
    uint8_t  flags;          // +0x20 bit0=progressive
    uint8_t  pad_21[3];
    uint32_t xOffset;        // +0x24
    uint32_t yOffset;        // +0x28
    uint32_t subsampling;    // +0x2C
    uint64_t asyncToken;     // +0x30 非零=async
    uint64_t asyncToken2;    // +0x38
    uint64_t field_40;       // +0x40
    uint32_t codecID;        // +0x48
    uint32_t outWidth;       // +0x4C
    uint32_t outHeight;      // +0x50
    uint32_t field_54;       // +0x54
} jpeg_req_t;

_Static_assert(sizeof(jpeg_req_t) == 0x58, "must be 0x58");

static void scalar_probe(io_connect_t conn, uint32_t sel)
{
    uint64_t out[8]; memset(out, 0, sizeof(out));
    uint32_t outCnt = 8;
    kern_return_t r = IOConnectCallScalarMethod(conn, sel, NULL, 0, out, &outCnt);
    L(@"  [scalar] sel %2u -> 0x%08x %-16s (outCnt=%u)", sel, (uint32_t)r, kr_name(r), outCnt);
}

static void struct_probe(io_connect_t conn, uint32_t sel, const void *in, size_t inSz, size_t outSz, const char *tag)
{
    uint8_t out[0x1000];
    memset(out, 0, sizeof(out));
    size_t os = outSz;
    kern_return_t r = IOConnectCallStructMethod(conn, sel, in, inSz, out, &os);
    L(@"  [struct %s] sel %2u in=0x%zx out=0x%zx -> 0x%08x %-16s (returned outSize=0x%zx)",
      tag, sel, inSz, outSz, (uint32_t)r, kr_name(r), os);
}

static void run(void)
{
    L(@"===== AppleJPEGDriver structured probe =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());

    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) return;

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    L(@"[2] IOServiceOpen(type=0) kr=0x%08x %s conn=0x%08x",
      (uint32_t)kr, kr_name(kr), conn);
    if (kr != KERN_SUCCESS) { IOObjectRelease(svc); return; }

    // ---- A: 无参 scalar，复现之前的结果（作对照）----
    L(@"");
    L(@"=== A. scalar (0 args) — 对照组，应与之前一致（全 NotAttached）===");
    for (uint32_t s = 0; s <= 10; s++) scalar_probe(conn, s);

    // ---- B: 正确尺寸的 struct 调用 ----
    L(@"");
    L(@"=== B. struct 0x58 —— 按公开 PoC 的方式调 sel 1 (decode) ===");
    jpeg_req_t in; memset(&in, 0, sizeof(in));
    struct_probe(conn, 1, &in, sizeof(in), sizeof(in), "sel1 zeroed");

    // ---- C: 结构性探测：不同 inSize 对同一 selector ----
    L(@"");
    L(@"=== C. sel 1 的 inSize 敏感性（判断 checkStructureInputSize 是否 == 0x58）===");
    uint8_t big[0x1000]; memset(big, 0, sizeof(big));
    struct_probe(conn, 1, big, 0x00,  0x58, "in=0x00");
    struct_probe(conn, 1, big, 0x10,  0x58, "in=0x10");
    struct_probe(conn, 1, big, 0x40,  0x58, "in=0x40");
    struct_probe(conn, 1, big, 0x58,  0x58, "in=0x58");
    struct_probe(conn, 1, big, 0x60,  0x58, "in=0x60");
    struct_probe(conn, 1, big, 0x100, 0x58, "in=0x100");
    struct_probe(conn, 1, big, 0xDA0, 0xDA0, "in=0xDA0");

    // ---- D: sel 3 (encode) 与 sel 0/2 的 struct 形态 ----
    L(@"");
    L(@"=== D. sel 3 (encode) 与其他 selector 的 struct 形态 ===");
    struct_probe(conn, 3, &in, sizeof(in), sizeof(in), "sel3 zeroed");
    struct_probe(conn, 0, &in, sizeof(in), sizeof(in), "sel0 as struct");
    struct_probe(conn, 2, &in, sizeof(in), sizeof(in), "sel2 as struct");

    // ---- E: 表长判定 ----
    L(@"");
    L(@"=== E. 表长判定（10 之外是否 Unsupported）===");
    struct_probe(conn, 10, &in, sizeof(in), sizeof(in), "sel10");
    struct_probe(conn, 11, &in, sizeof(in), sizeof(in), "sel11");
    struct_probe(conn, 0x20, &in, sizeof(in), sizeof(in), "sel0x20");

    L(@"");
    L(@"===== probe done =====");
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
    if (!gQ) gQ = dispatch_queue_create("jpegp3.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:8] ?: [UIFont systemFontOfSize:8];
    gView.editable = NO;
    gView.text = @"JPEG structured probe starting...\n";
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
