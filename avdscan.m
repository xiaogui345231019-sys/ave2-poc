//
//  avdscan.m — 二分找 AppleAVD 的尺寸上限（解码路线）
//
//  起因（vtdecode 的 syslog 揭开）：
//    · 解码走的是 AppleAVD，不是 AppleAVE2（AVE2 = 编码器，AVD = 解码器）
//    · CMVideoFormatDescriptionCreate 完全不校验尺寸（全部 noErr）
//    · 但 VTDecompressionSessionCreate 拒了：1080p → -8971，大尺寸 → -12910
//    · syslog 里有 `AVD_AllowBitstreamToChangeFrameDimensions 0`（码流禁改尺寸）
//
//  本包要回答：**AVD 的尺寸上限在哪**
//    固定 W=1920，H 从 1080 一路加到 2^21，观察 -8971 → -12910 的翻转点
//    再测方阵（1920² → 65535²），看单维是否有独立上限
//
//  判读：
//    · 若翻转点对应某个"单维上限"（如 16384 / 32768 / 65535）⇒ AVD 有单维约束
//    · 若翻转点对应 W*H 越过 2^31              ⇒ AVD 用 32 位乘积判断（和 AVE2 同形！）
//    · 若始终 -8971 不变                       ⇒ 尺寸无关，是缺 SPS/PPS
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
    NSLog(@"AVDSCAN %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"avdscan.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
        }
    });
}

typedef void *CMVideoFormatDescriptionRef;
typedef void *VTDecompressionSessionRef;

static const uint32_t kCMVideoCodecType_HEVC = 0x68766331;   // 'hvc1'

typedef int32_t (*fn_fd_t)(void *, uint32_t, int32_t, int32_t, void *, CMVideoFormatDescriptionRef *);
typedef int32_t (*fn_ds_t)(void *, CMVideoFormatDescriptionRef, void *, void *, void *, VTDecompressionSessionRef *);
typedef void    (*fn_inv_t)(VTDecompressionSessionRef);

static fn_fd_t  p_fd  = NULL;
static fn_ds_t  p_ds  = NULL;
static fn_inv_t p_inv = NULL;

// 关键错误码（实测 -8971 与 -12910，含义见报告）
static const char *st_name(int32_t st)
{
    switch (st) {
        case 0:      return "noErr";
        case -8971:  return "FIG_BASE_OBJ_ERR?";        // 1080p 也返回这个
        case -12910: return "kVTDecoderUnsupportedFmt"; // 大尺寸返回这个
        case -12911: return "kVTDecoderMalfunction";
        case -12913: return "kVTDecoderNotAvailNow";
        case -12902: return "kVTParameterErr";
        case -12904: return "kVTAllocationFailed";
        case -12782: return "kCMFD_InvalidParameter";
        case -12783: return "kCMFD_AllocationFailed";
        case -12787: return "kCMFD_InvalidDimensions";
        default:     return "?";
    }
}

// 返回 session 创建结果（只创建，不 Decode）
static int32_t probe(int32_t w, int32_t h)
{
    CMVideoFormatDescriptionRef fd = NULL;
    int32_t st = p_fd(NULL, kCMVideoCodecType_HEVC, w, h, NULL, &fd);
    if (st != 0 || !fd) return st;

    VTDecompressionSessionRef s = NULL;
    st = p_ds(NULL, fd, NULL, NULL, NULL, &s);
    if (st == 0 && s) {
        if (p_inv) p_inv(s);
        CFRelease((CFTypeRef)s);
    }
    CFRelease((CFTypeRef)fd);
    return st;
}

static void line(int32_t w, int32_t h, int32_t st, const char *note)
{
    int64_t prod = (int64_t)w * (int64_t)h;
    double ratio = (double)prod / 2147483648.0;
    const char *flag = "";
    if (st == 0) flag = "   ★ session 建成";
    else if (st == -12910) flag = "   [格式/尺寸被拒]";
    else if (st == -8971) flag = "   [基线型失败]";
    L(@"  %6d x %-8d W*H=%-13lld (%.3fx2^31) -> %6d %-22s%s  %s",
      w, h, (long long)prod, ratio, st, st_name(st), flag, note ? note : "");
}

static void run(void)
{
    L(@"===== AVD 尺寸上限扫描 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    void *vt = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", RTLD_NOW);
    void *cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW);
    if (!vt || !cm) { L(@"加载失败"); SetStatus(@"加载失败"); return; }

    p_fd  = (fn_fd_t)dlsym(cm, "CMVideoFormatDescriptionCreate");
    p_ds  = (fn_ds_t)dlsym(vt, "VTDecompressionSessionCreate");
    p_inv = (fn_inv_t)dlsym(vt, "VTDecompressionSessionInvalidate");
    if (!p_fd || !p_ds) { L(@"dlsym 失败"); SetStatus(@"dlsym 失败"); return; }
    L(@"[ok] dlsym 完成");

    // ---- Phase 1: W 固定 1920，H 递增 ----
    L(@"");
    L(@"=== Phase 1: W=1920 固定，H 递增（找翻转点）===");
    SetStatus(@"Phase 1: W=1920");
    int32_t ws = 1920;
    int32_t hs[] = {
        1080, 2160, 4320, 8640, 17280, 34560, 69120, 138240, 276480,
        552960, 1000000, 1048576, 1100000,
        1118481,   // 2^31 / 1920 的向上取整附近
        1118482,   // 刚过 2^31
        1500000, 2000000, 2097152, 4194304
    };
    int32_t prev = -999;
    int flipH = -1;
    for (int i = 0; i < (int)(sizeof(hs)/sizeof(hs[0])); i++) {
        const char *note = "";
        if (hs[i] == 1118482) note = "← 刚过 2^31";
        else if (hs[i] == 1048576) note = "= 2^20";
        else if (hs[i] == 2097152) note = "= 2^21";
        int32_t st = probe(ws, hs[i]);
        line(ws, hs[i], st, note);
        if (prev != -999 && prev != st && flipH < 0) {
            flipH = hs[i];
            L(@"      ★★ 翻转点：H=%d 时返回码从 %d 变成 %d", hs[i], prev, st);
        }
        prev = st;
        usleep(120 * 1000);
    }

    // ---- Phase 2: 方阵 ----
    L(@"");
    L(@"=== Phase 2: 方阵 W=H ===");
    SetStatus(@"Phase 2: 方阵");
    int32_t sq[] = {1080, 1920, 4096, 8192, 16384, 24576, 32768, 46341, 65535};
    prev = -999;
    int flipSq = -1;
    for (int i = 0; i < (int)(sizeof(sq)/sizeof(sq[0])); i++) {
        const char *note = "";
        if (sq[i] == 46341) note = "≈ sqrt(2^31)";
        int32_t st = probe(sq[i], sq[i]);
        line(sq[i], sq[i], st, note);
        if (prev != -999 && prev != st && flipSq < 0) {
            flipSq = sq[i];
            L(@"      ★★ 翻转点：方阵边长 %d 时 %d -> %d", sq[i], prev, st);
        }
        prev = st;
        usleep(120 * 1000);
    }

    // ---- Phase 3: 极小尺寸对照（确认 -8971 是否与尺寸无关）----
    L(@"");
    L(@"=== Phase 3: 极小尺寸（确认基线失败码）===");
    SetStatus(@"Phase 3: 极小");
    int32_t tiny[][2] = { {16,16}, {64,64}, {256,256}, {640,480}, {1280,720} };
    for (int i = 0; i < 5; i++) {
        int32_t st = probe(tiny[i][0], tiny[i][1]);
        line(tiny[i][0], tiny[i][1], st, "");
        usleep(120 * 1000);
    }

    // ---- 汇总 ----
    L(@"");
    L(@"===== 汇总 =====");
    if (flipH > 0) L(@"  Phase1 翻转点: H=%d（W=1920）", flipH);
    else           L(@"  Phase1 无翻转：返回码全程一致");
    if (flipSq > 0) L(@"  Phase2 翻转点: 边长=%d", flipSq);
    else            L(@"  Phase2 无翻转");
    L(@"");
    L(@"  判读：");
    L(@"    · 翻转点若对应 W*H 越过 2^31  ⇒ AVD 也用 32 位乘积判断，与 AVE2 同形");
    L(@"    · 翻转点若对应单维上限（16384/32768）⇒ AVD 有单维约束");
    L(@"    · 全程 -8971 不变 ⇒ 尺寸无关，是 formatDescription 缺 SPS/PPS 扩展");
    SetStatus(@"完成，看日志");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("avdscan.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"avdscan...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 84, self.window.bounds.size.width, h - 84)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:8] ?: [UIFont systemFontOfSize:8];
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
