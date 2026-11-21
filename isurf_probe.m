//
//  isurf_probe.m — IOSurfaceRoot sel 6 地址控制验证（阶段 0.8）
//
//  背景（离线审计结论，a14_18.6.2_com.apple.iokit.IOSurface）：
//    IOExternalMethodDispatch 表 = 40 字节/项、57 项，主表 @0x7e2fc48
//    sel 6: handler 0x9e82938 → 0x9e856a4，sin = 0x20（固定 32 字节）
//           前置只查 [self+0x128] < 0x4000（client limit）
//           解析：structureInput[0..7]   → OSNumber(v,64) → 属性键 "IOSurfaceAddress"
//                 structureInput[8+i*4]   → u32 × 6     → Width/Height/PixelFormat/BytesPerElement/?/AllocSize
//           然后 bl 0x9e7e468 创建
//    沙箱 App 无 gpu-restricted ⇒ [self+0x127]==0 ⇒ 走完整主表，sel 6 可用
//
//  本工具要回答的唯一问题：
//    **IOSurfaceAddress 这个键，在创建时到底被不被当真？**
//    做法：用四组显著不同的地址各创建一次，看返回码差异。
//      A. address = 0                      （空指针，基线）
//      B. address = 0x1000                 （低地址）
//      C. address = 0x800000000            （A14 上可能的合法物理内存区：6GB 机器的高端）
//      D. address = 0xdeadbeef000          （明显的野地址）
//    - 四组都成功  → 地址不被校验（甚至可能不被使用）→ 需要进一步验证是否真的映射
//    - 只有 A 成功  → 说明地址必须为空（不受控）
//    - B/C 成功而 D 失败 → 说明有区间校验（但仍是强线索）
//
//  安全性：只创建 IOSurface，不读写它们的内容；不会造成内存破坏。
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

    NSLog(@"ISURF %@", s);

    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"isurf.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }

    dispatch_async(gQ, ^{
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length, 0)]; }
        });
    });
}

// sel 6 的输入布局（共 0x20 = 32 字节，小端）
typedef struct __attribute__((packed)) {
    uint64_t address;          // +0x00  → IOSurfaceAddress
    uint32_t width;            // +0x08
    uint32_t height;           // +0x0c
    uint32_t pixelFormat;      // +0x10
    uint32_t bytesPerElement;  // +0x14
    uint32_t unknown;          // +0x18  （串 0x76fe31c，未解）
    uint32_t allocSize;        // +0x1c  → IOSurfaceAllocSize
} isurf_req_t;

static void try_create(io_connect_t conn, uint64_t addr, uint32_t w, uint32_t h,
                       uint32_t pf, uint32_t bpe, uint32_t x, uint32_t alloc,
                       const char *tag)
{
    isurf_req_t req;
    memset(&req, 0, sizeof(req));
    req.address = addr; req.width = w; req.height = h;
    req.pixelFormat = pf; req.bytesPerElement = bpe;
    req.unknown = x; req.allocSize = alloc;

    uint8_t out[0xc68];
    memset(out, 0, sizeof(out));
    size_t outSize = sizeof(out);

    kern_return_t kr = IOConnectCallStructMethod(conn, 6, &req, sizeof(req), out, &outSize);

    L(@"[%s] addr=0x%llx w=%u h=%u pf=0x%x bpe=%u unk=%u alloc=%u",
      tag, (unsigned long long)addr, w, h, pf, bpe, x, alloc);
    L(@"     kr=0x%08x %s  outSize=0x%zx", (uint32_t)kr, kr_name(kr), outSize);

    if (kr == KERN_SUCCESS) {
        // 把输出前 0x40 字节打出来，找 surface ID
        NSMutableString *hex = [NSMutableString string];
        for (size_t i = 0; i < 0x40 && i < outSize; i++) {
            [hex appendFormat:@"%02x", out[i]];
            if ((i & 7) == 7) [hex appendString:@" "];
        }
        L(@"     out[0..0x3f] = %@", hex);
        // 前 4/8 字节大概率是 ID
        uint32_t id32 = *(uint32_t *)&out[0];
        L(@"     u32@0x00 = %u (0x%x)", id32, id32);
    }
}

static void run(void)
{
    L(@"===== IOSurfaceRoot sel6 address-control probe =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());

    CFMutableDictionaryRef m = IOServiceMatching("IOSurfaceRoot");
    if (!m) { L(@"[1] matching NULL"); return; }
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) { L(@"[1] FAILED no service"); return; }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    L(@"[2] IOServiceOpen(type=0) kr=0x%08x %s conn=0x%08x",
      (uint32_t)kr, kr_name(kr), conn);
    if (kr != KERN_SUCCESS) { IOObjectRelease(svc); return; }

    L(@"");
    L(@"--- baseline: sane geometry, address = 0 ---");
    try_create(conn, 0, 64, 64, 0x42475241 /* 'BGRA' */, 4, 0, 64*64*4, "A addr0");

    L(@"");
    L(@"--- low address ---");
    try_create(conn, 0x1000ULL, 64, 64, 0x42475241, 4, 0, 64*64*4, "B 0x1000");

    L(@"");
    L(@"--- plausible physical region (6GB machine) ---");
    try_create(conn, 0x800000000ULL, 64, 64, 0x42475241, 4, 0, 64*64*4, "C 0x8_00000000");

    L(@"");
    L(@"--- obviously bogus ---");
    try_create(conn, 0xdeadbeef000ULL, 64, 64, 0x42475241, 4, 0, 64*64*4, "D 0xdeadbeef000");

    L(@"");
    L(@"--- zero size, valid addr ---");
    try_create(conn, 0x1000ULL, 0, 0, 0x42475241, 4, 0, 0, "E zero-geom");

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
    if (!gQ) gQ = dispatch_queue_create("isurf.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    gView.text = @"IOSurface sel6 probe starting...\n";
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
