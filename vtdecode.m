//
//  vtdecode.m — 解码路线：用 formatDescription 直接声明超大尺寸
//
//  为什么换解码（vtframe 的结论）：
//    编码路线要求真实的 W×H pixel buffer（16384×131072×4 = 8.6 TB），物理不可分配；
//    VT 会静默跳过不匹配的 buffer（返回 noErr 但不调 IO_Start，
//    syslog 里 L1/L2 完全没有 `Client:` / `Resolution:` / `FwLog`）。
//    ⇒ 编码路线到此为止。
//
//  解码路线不同：**输入是码流字节，尺寸写在 formatDescription 里**，不需要 W×H 的输入 buffer。
//    所以可以用 CMVideoFormatDescriptionCreate 直接声明 65535×65535。
//
//  本包做三件事（每级都只 Create，不 Decode —— 先看 VT 接不接受）：
//    L0  1920×1080      基线
//    L1  16384×131073   刚过 2^31
//    L2  65535×65535    最大方阵（4.29e9）
//
//  每级：
//    [1] CMVideoFormatDescriptionCreate(NULL, 'hvc1', W, H, NULL, &fd)
//    [2] VTDecompressionSessionCreate(NULL, fd, NULL, NULL, NULL, &session)
//    [3] 报告返回码；不等 DecodeFrame
//
//  ★ 如果 L1/L2 的 formatDescription 或 session 创建成功，
//    syslog 里应该出现 AVE2 的 open，甚至 `Resolution: 65535x65535`。
//  ★ 全部安全：不提交任何帧，不分配大 buffer。
//

#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <unistd.h>

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static UILabel       *gStatus = nil;
static dispatch_queue_t gQ = nil;

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"VTDEC %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vtdecode.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightBold];
        }
    });
}

typedef void *CMVideoFormatDescriptionRef;
typedef void *VTDecompressionSessionRef;

static const uint32_t kCMVideoCodecType_HEVC = 0x68766331;      // 'hvc1'
static const uint32_t kCMVideoCodecType_H264 = 0x61766331;      // 'avc1'

typedef int32_t (*fn_fd_create_t)(void *, uint32_t, int32_t, int32_t, void *, CMVideoFormatDescriptionRef *);
typedef int32_t (*fn_ds_create_t)(void *, CMVideoFormatDescriptionRef, void *, void *, void *, VTDecompressionSessionRef *);
typedef void    (*fn_ds_invalidate_t)(VTDecompressionSessionRef);

static fn_fd_create_t     p_fd_create  = NULL;
static fn_ds_create_t     p_ds_create  = NULL;
static fn_ds_invalidate_t p_ds_inval   = NULL;

static const char *osstatus_name(int32_t st)
{
    switch (st) {
        case 0:      return "noErr";
        case -12780: return "kCMBlockBufferBadCustomBlockSourceErr";
        case -12782: return "kCMFormatDescriptionError_InvalidParameter";
        case -12783: return "kCMFormatDescriptionError_AllocationFailed";
        case -12785: return "kCMFormatDescriptionBridgeError_InvalidParameter";
        case -12786: return "kCMFormatDescriptionBridgeError_InvalidSlice";
        case -12787: return "kCMFormatDescriptionBridgeError_InvalidDimensions";
        case -12902: return "kVTParameterErr";
        case -12903: return "kVTInvalidSessionErr";
        case -12904: return "kVTAllocationFailedErr";
        case -12906: return "kVTDecompressionFailedErr";
        case -12907: return "kVTBadDataErr";
        case -12908: return "kVTNotSupportedErr";
        case -12909: return "kVTPropertyNotSupportedErr";
        case -8969:  return "kCMFormatDescriptionError_InvalidParameter2";
        case -50:    return "paramErr";
        case -108:   return "memFullErr";
        default:     return "?";
    }
}

static void run_level(int n, int32_t w, int32_t h, uint32_t codec, const char *desc)
{
    int64_t prod = (int64_t)w * (int64_t)h;
    double ratio = (double)prod / 2147483648.0;

    L(@"");
    L(@"========== L%d: %s ==========", n, desc);
    L(@"    %d x %d   W*H = %lld  (%.3f x 2^31)   codec=%c%c%c%c",
      w, h, (long long)prod, ratio,
      (char)(codec>>24),(char)(codec>>16),(char)(codec>>8),(char)codec);
    SetStatus([NSString stringWithFormat:@"L%d: %dx%d", n, w, h]);

    // [1] FormatDescription
    CMVideoFormatDescriptionRef fd = NULL;
    int32_t st = p_fd_create(NULL, codec, w, h, NULL, &fd);
    L(@"  [1] CMVideoFormatDescriptionCreate -> %d %s  fd=%p", st, osstatus_name(st), fd);
    if (st != 0 || !fd) {
        L(@"      失败，跳过 session 创建");
        return;
    }

    // [2] DecompressionSession
    VTDecompressionSessionRef s = NULL;
    st = p_ds_create(NULL, fd, NULL, NULL, NULL, &s);
    L(@"  [2] VTDecompressionSessionCreate -> %d %s  session=%p", st, osstatus_name(st), s);

    if (st == 0 && s) {
        L(@"      ★ session 建成功 —— AVE2 可能已经收到这个尺寸");
        if (p_ds_inval) p_ds_inval(s);
        CFRelease((CFTypeRef)s);
    }

    CFRelease((CFTypeRef)fd);
    L(@"      完成");
}

static void run(void)
{
    L(@"===== 解码路线：formatDescription 直接声明超大尺寸 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    void *vt = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", RTLD_NOW);
    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW);
    L(@"[dlopen] VideoToolbox = %p  CoreMedia = %p", vt, cm);
    if (!vt || !cm) { L(@"加载失败"); SetStatus(@"加载失败"); return; }

    p_fd_create  = (fn_fd_create_t)dlsym(cm, "CMVideoFormatDescriptionCreate");
    p_ds_create  = (fn_ds_create_t)dlsym(vt, "VTDecompressionSessionCreate");
    p_ds_inval   = (fn_ds_invalidate_t)dlsym(vt, "VTDecompressionSessionInvalidate");

    L(@"[dlsym] CMVideoFormatDescriptionCreate = %p", p_fd_create);
    L(@"[dlsym] VTDecompressionSessionCreate   = %p", p_ds_create);
    L(@"[dlsym] VTDecompressionSessionInvalidate = %p", p_ds_inval);
    if (!p_fd_create || !p_ds_create) { L(@"dlsym 失败"); SetStatus(@"dlsym 失败"); return; }

    // L0 基线
    run_level(0, 1920, 1080, kCMVideoCodecType_HEVC, "baseline 1080p HEVC");
    sleep(2);

    // L1 刚过 2^31
    run_level(1, 16384, 131073, kCMVideoCodecType_HEVC, "★ 16384 x 131073（刚过 2^31）");
    sleep(2);

    // L2 最大方阵
    run_level(2, 65535, 65535, kCMVideoCodecType_HEVC, "★ 65535 x 65535（4.29e9）");
    sleep(2);

    // L3 H264 对照
    run_level(3, 65535, 65535, kCMVideoCodecType_H264, "65535 x 65535 H264");

    L(@"");
    L(@"===== 全部跑完，没有崩溃 =====");
    L(@"  下一步看 syslog 里 L1/L2 有没有 AVE2 的 open / Resolution:");
    L(@"    有 Resolution: 65535x65535 ⇒ AVE2 收到溢出尺寸，下一步做 DecodeFrame");
    L(@"    只有 open 无 Resolution    ⇒ 要真正 DecodeFrame 才进编码器");

    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("vtdecode.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"vtdecode...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 90, self.window.bounds.size.width, h - 90)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:9] ?: [UIFont systemFontOfSize:9];
    gView.editable = NO;
    [vc.view addSubview:gView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        @autoreleasepool { run(); }
    });
    return YES;
}
@end

int main(int argc, char *argv[])
{
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); }
}
