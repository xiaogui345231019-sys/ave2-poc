//
//  vtsize.m — 问一个问题的探针：VideoToolbox 会不会把调用方给的 W/H
//              原样写进 AVE2 的 VideoParams+0x698/+0x69C（还是先裁剪/校验）
//
//  背景（子代理 xpc-ave2-entry-map.md 的结论）：
//    · 全系统只有 7 个二进制持 AppleAVE2UserClient entitlement，
//      其中 usr/libexec/videocodecd 是唯一「为所有 app 服务」的
//    · app 调 VideoToolbox → com.apple.coremedia.videocodecd.compressionsession
//      → videocodecd → 用自己的 entitlement 打开 AVE2
//    · CoreMedia FeatureFlags: SeparateCodecProcess=Enabled / _Encode=Enabled ⇒ 活的
//
//  ★ 可控输入不是畸形码流，而是 **VTCompressionSessionCreate 的 width/height（显式 int32）**
//    AVE2 的 AVE_Client_CheckInfo 编码/解码共用同一个函数，缺 iPixelProduct<=2147483647 检查
//    ⇒ 一次 VTCompressionSessionCreate 就可能把 W*H > 2^31 送进 AVE2
//
//  本探针只问一件事：**VT 入口有没有尺寸上限？在哪？**
//    用一个递增的矩阵，从正常值扫到 2^31 以上，看 OSStatus 在哪里翻转。
//
//  判读：
//    · 某组 W*H > 2^31 返回 0（noErr）  ⇒ VT 不挡，AVE2 吃到溢出值 ⇒ 链条通了
//    · 全部 > 2^31 的组返回错误         ⇒ VT 层有上限，需换解码路线（SPS 宽高）
//    · 找到翻转点                        ⇒ 那就是 VT 的校验上限，记录下来
//
//  安全性：只创建 session 后立刻 invalidate，不提交任何帧、不编任何数据。
//        即使 W/H 是畸形值，也只会走到「分配失败」或「参数被拒」，不会触发编码流水线。
//        零 panic 风险（真正的越界写发生在 IO_Start 之后的 DMA 阶段，本探针不调）。
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
    NSLog(@"VTSIZE %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vtsize.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
        }
    });
}

// CoreMedia 常量（直接写数值，避免包含 CoreMedia 头）
static const uint32_t kCMVideoCodecType_HEVC = 0x68766331;   // 'hvc1'
static const uint32_t kCMVideoCodecType_H264 = 0x61766331;   // 'avc1'

typedef void *VTCompressionSessionRef;
typedef void *CFAllocatorRef_t;
typedef void *CFDictionaryRef_t;

typedef int32_t (*fn_create_t)(CFAllocatorRef_t, int32_t, int32_t, uint32_t,
                               CFDictionaryRef_t, CFDictionaryRef_t, CFAllocatorRef_t,
                               CFDictionaryRef_t, void *, VTCompressionSessionRef *);
typedef void    (*fn_invalidate_t)(VTCompressionSessionRef);

static fn_create_t     p_VTCompressionSessionCreate    = NULL;
static fn_invalidate_t p_VTCompressionSessionInvalidate = NULL;

static const char *osstatus_name(int32_t st)
{
    switch (st) {
        case 0:            return "noErr";
        case -12902:       return "kVTParameterErr";
        case -12903:       return "kVTInvalidSessionErr";
        case -12904:       return "kVTAllocationFailedErr";
        case -12905:       return "kVTPixelTransferNotSupportedErr";
        case -12906:       return "kVTDecompressionFailedErr";
        case -12907:       return "kVTBadDataErr";
        case -12908:       return "kVTNotSupportedErr";
        case -12909:       return "kVTPropertyNotSupportedErr";
        case -12780:       return "kCMBlockBufferBadCustomBlockSourceErr";
        case -12782:       return "kCMFormatDescriptionError_InvalidParameter";
        case -12783:       return "kCMFormatDescriptionError_AllocationFailed";
        case -12785:       return "kCMFormatDescriptionBridgeError_InvalidParameter";
        case -12786:       return "kCMFormatDescriptionBridgeError_InvalidSlice";
        case -12787:       return "kCMFormatDescriptionBridgeError_InvalidDimensions";
        case -50:          return "paramErr";
        case -108:         return "memFullErr";
        case -6661:        return "kCVReturnInvalidSize";
        case -6660:        return "kCVReturnInvalidArgument";
        default:           return "?";
    }
}

typedef struct {
    int32_t w, h;
    const char *tag;
} case_t;

static void try_one(int32_t w, int32_t h, uint32_t codec, const char *tag)
{
    int64_t prod = (int64_t)w * (int64_t)h;
    double ratio = (double)prod / 2147483648.0;   // 相对 2^31

    VTCompressionSessionRef s = NULL;
    int32_t st = p_VTCompressionSessionCreate(NULL, w, h, codec,
                                              NULL, NULL, NULL, NULL, NULL, &s);
    const char *r = osstatus_name(st);

    L(@"  %-22s %6d x %-7d codec=%c%c%c%c  W*H=%-13lld (%.3f x 2^31)  -> %d %s%s",
      tag, w, h,
      (char)(codec>>24), (char)(codec>>16), (char)(codec>>8), (char)codec,
      (long long)prod, ratio, st, r,
      (st == 0 ? "   ★ 成功" : ""));

    if (st == 0 && s) {
        if (p_VTCompressionSessionInvalidate) p_VTCompressionSessionInvalidate(s);
        CFRelease((CFTypeRef)s);
    }
    usleep(200 * 1000);   // 给 videocodecd 一点时间处理
}

static void run(void)
{
    L(@"===== VT dimension limit probe =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"");

    // 加载 VideoToolbox
    const char *paths[] = {
        "/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox",
        "/System/Library/PrivateFrameworks/VideoToolbox.framework/VideoToolbox",
        NULL
    };
    void *vt = NULL;
    for (int i = 0; paths[i]; i++) {
        vt = dlopen(paths[i], RTLD_NOW);
        if (vt) { L(@"[dlopen] %s -> OK", paths[i]); break; }
        else L(@"[dlopen] %s -> %s", paths[i], dlerror());
    }
    if (!vt) {
        L(@"VideoToolbox 加载失败，终止");
        SetStatus(@"VideoToolbox 加载失败");
        return;
    }

    p_VTCompressionSessionCreate     = (fn_create_t)dlsym(vt, "VTCompressionSessionCreate");
    p_VTCompressionSessionInvalidate = (fn_invalidate_t)dlsym(vt, "VTCompressionSessionInvalidate");
    L(@"[dlsym] VTCompressionSessionCreate     = %p", p_VTCompressionSessionCreate);
    L(@"[dlsym] VTCompressionSessionInvalidate = %p", p_VTCompressionSessionInvalidate);
    if (!p_VTCompressionSessionCreate) {
        L(@"dlsym 失败，终止");
        SetStatus(@"dlsym 失败");
        return;
    }
    L(@"");

    // ===== 阶段 1：基线（正常尺寸，确认 API 可用）=====
    L(@"=== Phase 1: 基线（确认 API 可用）===");
    SetStatus(@"Phase 1: 基线");
    try_one(1920, 1080, kCMVideoCodecType_HEVC, "baseline 1080p");
    try_one(4096, 2160, kCMVideoCodecType_HEVC, "4K HEVC");
    try_one(1920, 1080, kCMVideoCodecType_H264, "baseline 1080p H264");
    L(@"");

    // ===== 阶段 2：逼近 2^31 =====
    L(@"=== Phase 2: 逼近 2^31（W 固定 16384，扫 H）===");
    L(@"  2^31 / 16384 = 131072（正好整除）");
    SetStatus(@"Phase 2: 逼近 2^31");
    int32_t W = 16384;
    int32_t hs[] = { 1080, 8192, 65536, 131071, 131072, 131073, 131074, 262144, 262160 };
    for (int i = 0; i < (int)(sizeof(hs)/sizeof(hs[0])); i++) {
        char tag[48];
        if (hs[i] == 131072)      snprintf(tag, sizeof(tag), "exactly 2^31");
        else if (hs[i] == 131071) snprintf(tag, sizeof(tag), "just below 2^31");
        else if (hs[i] == 131073) snprintf(tag, sizeof(tag), "just above 2^31");
        else if (hs[i] == 262160) snprintf(tag, sizeof(tag), "2x overflow");
        else snprintf(tag, sizeof(tag), "h=%d", hs[i]);
        try_one(W, hs[i], kCMVideoCodecType_HEVC, tag);
    }
    L(@"");

    // ===== 阶段 3：极端值 =====
    L(@"=== Phase 3: 极端尺寸 ===");
    SetStatus(@"Phase 3: 极端值");
    try_one(65535, 65535, kCMVideoCodecType_HEVC, "max square 65535^2");
    try_one(131072, 16384, kCMVideoCodecType_HEVC, "swapped W/H");
    try_one(2147483647, 2,  kCMVideoCodecType_HEVC, "INT32_MAX x 2");
    try_one(1, 1,           kCMVideoCodecType_HEVC, "1x1");
    try_one(0, 0,           kCMVideoCodecType_HEVC, "0x0");
    L(@"");

    // ===== 阶段 4：H264 也试一遍（不同编解码器可能有不同限制）=====
    L(@"=== Phase 4: H264 对照 ===");
    SetStatus(@"Phase 4: H264");
    try_one(16384, 131072, kCMVideoCodecType_H264, "H264 exactly 2^31");
    try_one(16384, 131073, kCMVideoCodecType_H264, "H264 above 2^31");
    L(@"");

    L(@"===== 判读 =====");
    L(@"  · 若 \"just above 2^31\" 或更大 返回 0(noErr)");
    L(@"      ⇒ VT 入口不挡，AVE2 会吃到 W*H>2^31 的溢出值");
    L(@"      ⇒ 64747 链条打通，下一步做 IO_Start 真正触发");
    L(@"  · 若全部 >2^31 的组返错");
    L(@"      ⇒ VT 层有上限，需换解码路线（HEVC SPS 里 pic_width_in_luma_samples=65535）");
    L(@"  · 找翻转点（刚好在哪个 H 开始报错）= VT 的校验上限");
    L(@"");
    L(@"  请同时在 PC 上跑:");
    L(@"    python -m pymobiledevice3 syslog live | findstr /I \"videocodecd AVE2 appleave VT\"");

    SetStatus(@"完成，看日志");
    L(@"===== done =====");
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("vtsize.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 34)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"vtsize probe...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 90, self.window.bounds.size.width, h - 90)];
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
