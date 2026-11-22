//
//  ksscan.m — AppleKeyStore 精确尺寸探测（sin = 0x300）
//
//  离线已破解它的 dispatch 表：
//    · stride = 80 字节（0x50），44 项
//    · +0x00 fn / +0x38 sin = 0x300（768，全部 44 项相同）/ +0x40 cmd_id / +0x44 flags
//    · priv 串 = 0，dev 串 = 0（无 entitlement 门）
//    · 沙箱可 open（type 0，已实测 SUCCESS）
//
//  之前 gpuscan 传的尺寸是 0x18/0x30/0x58/0x80/0x100/0x400/0x1000 —— 没有 0x300，
//  所以全 BadArgument。本包用正确的 0x300 重测。
//
//  只测 8 个（用户指定“精准”）：
//    sel 0 / 1 / 16      ← 之前 0x18 全零就 SUCCESS（不依赖输入，零风险）
//    sel 5 / 19 / 20 / 21 / 22  ← 之前返回 x（需要参数）
//
//  对每个 sel 用三种填充，看返回码是否变化（变化 = 它读了输入）
//    A. 全零
//    B. 递增 (0,1,2,...,255,0,1,...)
//    C. 全 0xFF
//
//  ★ 风险提示：AppleKeyStore 是密钥存储。虽然只测这 8 个（其余 36 个不碰），
//    但仍有极小概率触碰状态变更。若设备出现异常，重启即可恢复。
//

#import <UIKit/UIKit.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static UILabel       *gStatus = nil;
static dispatch_queue_t gQ = nil;

static const char *kr_name(kern_return_t kr)
{
    switch ((uint32_t)kr) {
        case 0:          return "SUCCESS";
        case 0xe00002b0: return "NoSuchClass";
        case 0xe00002bc: return "Error";
        case 0xe00002be: return "NoResources";
        case 0xe00002c0: return "NoDevice";
        case 0xe00002c1: return "NotPrivileged";
        case 0xe00002c2: return "BadArgument";
        case 0xe00002c5: return "ExclusiveAccess";
        case 0xe00002c7: return "Unsupported";
        case 0xe00002c9: return "InternalError";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002d4: return "Busy";
        case 0xe00002d8: return "NotAttached";
        case 0xe00002e2: return "NotPermitted";
        case 0xe00002f0: return "NotFound";
        default:         return "?";
    }
}

static void L(NSString *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    NSString *s = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"ksscan.log"];
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

static const size_t SIN = 0x300;

// 一次调用，返回 kr，并把 out 前 4 个 u32 打出来
static kern_return_t call_once(io_connect_t conn, uint32_t sel, int pat, const char *patName)
{
    uint8_t *buf = malloc(SIN);
    if (!buf) return 0xffffffff;
    if (pat == 0) {
        memset(buf, 0, SIN);
    } else if (pat == 1) {
        for (size_t i = 0; i < SIN; i++) buf[i] = (uint8_t)(i & 0xFF);
    } else {
        memset(buf, 0xFF, SIN);
    }

    uint8_t out[0x400]; memset(out, 0, sizeof(out));
    size_t os = sizeof(out);
    kern_return_t kr = IOConnectCallStructMethod(conn, sel, buf, SIN, out, &os);

    uint32_t o0 = 0, o1 = 0, o2 = 0, o3 = 0;
    if (os >= 16) {
        o0 = *(uint32_t*)(out+0); o1 = *(uint32_t*)(out+4);
        o2 = *(uint32_t*)(out+8); o3 = *(uint32_t*)(out+12);
    }
    L(@"    sel %-2u [%-4s] -> 0x%08x %-15s outSize=0x%04zx  out=%08x %08x %08x %08x",
      sel, patName, (uint32_t)kr, kr_name(kr), os, o0, o1, o2, o3);
    free(buf);
    return kr;
}

static void run(void)
{
    L(@"===== AppleKeyStore 精确尺寸探测（sin=0x300）=====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"  表结构: stride=80B / 44 项 / 全部 sin=0x300 / 无 entitlement 门");
    L(@"");

    CFMutableDictionaryRef m = IOServiceMatching("AppleKeyStore");
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    L(@"[1] service = 0x%08x", svc);
    if (svc == MACH_PORT_NULL) { L(@"  未匹配到"); SetStatus(@"未匹配"); return; }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0, &conn);
    L(@"[2] open(type=0) -> 0x%08x %s conn=0x%08x", (uint32_t)kr, kr_name(kr), conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { L(@"  打不开"); SetStatus(@"打不开"); return; }

    // ---- 8 个 selector × 3 种填充 ----
    uint32_t sels[] = {0, 1, 5, 16, 19, 20, 21, 22};
    const char *patNames[] = {"zero", "incr", "0xFF"};
    int nsel = sizeof(sels)/sizeof(sels[0]);

    L(@"");
    L(@"=== 8 个 selector × 3 种填充 ===");
    L(@"  （返回码随填充变化 = 它读了输入）");
    L(@"");

    for (int i = 0; i < nsel; i++) {
        SetStatus([NSString stringWithFormat:@"sel %u", sels[i]]);
        kern_return_t r0 = 0xffffffff, r1 = 0xffffffff, r2 = 0xffffffff;
        for (int p = 0; p < 3; p++) {
            kern_return_t r = call_once(conn, sels[i], p, patNames[p]);
            if (p == 0) r0 = r; else if (p == 1) r1 = r; else r2 = r;
            usleep(80 * 1000);
        }
        if (r0 != r1 || r1 != r2) {
            L(@"      ★★ 填充敏感！三种填充返回码不同 ⇒ 该 selector 读了 structureInput");
        } else if (r0 == 0) {
            L(@"      （三种都是 SUCCESS，且不依赖输入内容）");
        }
        L(@"");
    }

    IOServiceClose(conn);

    L(@"===== 判读 =====");
    L(@"  · 三种填充返回码不同 → ★ 真实数据处理点，值得深挖");
    L(@"  · 全 SUCCESS 且不随填充变 → 不读输入（可能是查询类）");
    L(@"  · 全 BadArgument → 0x300 也不对，说明还有更严的前置条件");
    L(@"  · 出现 0xe00002e2 NotPermitted → 说明该 selector 有 entitlement 门（与 priv 串=0 的结论矛盾，需复查）");
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
    if (!gQ) gQ = dispatch_queue_create("ksscan.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"ksscan...";
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
