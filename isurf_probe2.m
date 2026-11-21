//
//  isurf_probe2.m — 验证 alloc=0 时 IOSurfaceAddress 是否真的决定 base address
//
//  上一轮（isurfprobe / sel 6）实测结论：
//    A. addr=0    + 64x64 + alloc=16384  → SUCCESS，out[0]=0x0000000100638000（系统分配）
//    B. addr=0x1000 + 64x64 + alloc=16384 → NotAttached   （需要分配时非零地址被拒）
//    C. addr=0x800000000 + 同几何        → NotAttached
//    D. addr=0xdeadbeef000 + 同几何      → NotAttached
//    E. addr=0x1000 + 0x0 + alloc=0      → SUCCESS，out[0]=0x1000  ← 我们的值被原样接受
//
//  本轮要回答的唯一问题：
//    **E 那种 surface，IOSurfaceGetBaseAddress() 到底返回什么？**
//      · == 我们给的地址   → 地址控制成立（可造「指向任意地址的 IOSurface」）
//      · 系统分配的别的值  → 我们给的地址只是被记成属性（死路）
//      · 0 / NULL          → 无 backing，需后续绑定
//
//  做法：
//    1. 用 sel 6 建一个 address = 0x1234000、0x0、alloc=0 的 surface
//    2. 因为不知道 output 里哪个字段是 IOSurfaceID，所以**逐个 offset 暴力试** IOSurfaceLookup
//       （前 0x200 字节，每 4 字节一次；命中后打印该 surface 的全部可知属性）
//    3. 再建一个 address = 0 的对照组，确认「系统分配」长什么样
//
//  安全性：只创建 IOSurface 并读取其元数据，不读写其像素内容。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

// theos SDK 的 IOSurface.framework 只有 .tbd，没有 Headers/ → 手动声明公开 API
typedef struct __IOSurface *IOSurfaceRef;
typedef uint32_t IOSurfaceID;

extern IOSurfaceRef IOSurfaceLookup(IOSurfaceID csid);
extern IOSurfaceID  IOSurfaceGetID(IOSurfaceRef buffer);
extern void        *IOSurfaceGetBaseAddress(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetAllocSize(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetWidth(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetHeight(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetBytesPerRow(IOSurfaceRef buffer);

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

    NSLog(@"ISURF2 %@", s);

    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"isurf2.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }

    dispatch_async(gQ, ^{
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length, 0)]; }
        });
    });
}

typedef struct __attribute__((packed)) {
    uint64_t address;
    uint32_t width;
    uint32_t height;
    uint32_t pixelFormat;
    uint32_t bytesPerElement;
    uint32_t unknown;
    uint32_t allocSize;
} isurf_req_t;

// 在 output 缓冲里逐个 4 字节偏移试 IOSurfaceLookup，命中就打印全部属性
static int scan_for_surface(const uint8_t *out, size_t outSize, const char *tag, uint64_t wantedAddr)
{
    int hits = 0;
    size_t limit = outSize < 0x200 ? outSize : 0x200;

    for (size_t off = 0; off + 4 <= limit; off += 4) {
        uint32_t cand = *(const uint32_t *)(out + off);
        if (cand == 0) continue;

        IOSurfaceRef surf = IOSurfaceLookup(cand);
        if (!surf) continue;

        hits++;
        void *base = IOSurfaceGetBaseAddress(surf);
        size_t alloc = IOSurfaceGetAllocSize(surf);
        size_t w = IOSurfaceGetWidth(surf);
        size_t h = IOSurfaceGetHeight(surf);
        size_t bpr = IOSurfaceGetBytesPerRow(surf);
        uint32_t id = IOSurfaceGetID(surf);

        L(@"  [%s] *** HIT *** out+0x%zx = %u (0x%x)  GetID()=%u", tag, off, cand, cand, id);
        L(@"        base=0x%llx  alloc=%zu  w=%zu h=%zu bpr=%zu",
          (unsigned long long)(uintptr_t)base, alloc, w, h, bpr);

        if (base != NULL && wantedAddr != 0) {
            if ((uint64_t)(uintptr_t)base == wantedAddr) {
                L(@"        ★★★ BASE == WANTED ADDRESS 0x%llx  ⇒ 地址控制成立",
                  (unsigned long long)wantedAddr);
            } else {
                L(@"        base 与传入地址不符（传 0x%llx）", (unsigned long long)wantedAddr);
            }
        }
        if (base == NULL) {
            L(@"        base == NULL ⇒ 无 backing");
        }

        CFRelease(surf);
    }

    if (hits == 0) L(@"  [%s] 前 0x%zx 字节内没有任何可 lookup 的 ID", tag, limit);
    return hits;
}

static void create_and_inspect(io_connect_t conn, uint64_t addr, uint32_t w, uint32_t h,
                               uint32_t pf, uint32_t bpe, uint32_t unk, uint32_t alloc,
                               const char *tag)
{
    isurf_req_t req;
    memset(&req, 0, sizeof(req));
    req.address = addr; req.width = w; req.height = h;
    req.pixelFormat = pf; req.bytesPerElement = bpe;
    req.unknown = unk; req.allocSize = alloc;

    uint8_t out[0xc68];
    memset(out, 0, sizeof(out));
    size_t outSize = sizeof(out);

    kern_return_t kr = IOConnectCallStructMethod(conn, 6, &req, sizeof(req), out, &outSize);

    L(@"");
    L(@"=== [%s] addr=0x%llx w=%u h=%u pf=0x%x bpe=%u unk=%u alloc=%u ===",
      tag, (unsigned long long)addr, w, h, pf, bpe, unk, alloc);
    L(@"    kr=0x%08x %s  outSize=0x%zx", (uint32_t)kr, kr_name(kr), outSize);

    if (kr != KERN_SUCCESS) return;

    // 打印前 0x40 字节，便于人工核对
    NSMutableString *hex = [NSMutableString string];
    for (size_t i = 0; i < 0x40 && i < outSize; i++) {
        [hex appendFormat:@"%02x", out[i]];
        if ((i & 7) == 7) [hex appendString:@" "];
    }
    L(@"    out[0..0x3f] = %@", hex);

    scan_for_surface(out, outSize, tag, addr);
}

static void run(void)
{
    L(@"===== IOSurface sel6 base-address verification =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());

    CFMutableDictionaryRef m = IOServiceMatching("IOSurfaceRoot");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) return;

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    L(@"[2] open(type=0) kr=0x%08x %s conn=0x%08x", (uint32_t)kr, kr_name(kr), conn);
    if (kr != KERN_SUCCESS) { IOObjectRelease(svc); return; }

    const uint32_t PF = 0x42475241;  // 'BGRA'

    // 对照组：正常几何 + addr=0（系统自己分配，作为"正常长什么样"的参照）
    create_and_inspect(conn, 0, 64, 64, PF, 4, 0, 64*64*4, "CTRL addr0");

    // 主实验：alloc=0 + 非零地址（上一轮 E 组的形态）
    create_and_inspect(conn, 0x1234000ULL, 0, 0, PF, 4, 0, 0, "E1 0x1234000");

    // 换一个地址再试，验证"是不是真的跟着我们走"
    create_and_inspect(conn, 0x8000000ULL, 0, 0, PF, 4, 0, 0, "E2 0x8000000");

    // 极端值
    create_and_inspect(conn, 0xFFFFFFF000ULL, 0, 0, PF, 4, 0, 0, "E3 0xFFFFFFF000");

    L(@"");
    L(@"===== verification done =====");
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
    if (!gQ) gQ = dispatch_queue_create("isurf2.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    gView.text = @"IOSurface base-address verification starting...\n";
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
