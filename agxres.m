//
//  agxres.m — p20：掏出 sel 9 的完整输出，定位 resource group ID
//
//  p19 已证：Metal 预热后 sel 9 resType=3 四档全 SUCCESS。
//  现在要回答的是【输出结构里哪个字段是 resource group 的 ID/句柄】，
//  因为下一步建 type=3 命令需要它。
//
//  做法：
//    Phase 1  Metal 预热（复用 p19，必须 waitUntilCompleted）
//    Phase 2  open AGX type=1
//    Phase 3  sel 9 resType=3 × 5 次（cap 交替 0x80/0x40/0x100/0x200/0x80）
//             每次打印：outSize + 前 64 字节 hex + u32/u64 解释
//    Phase 4  调 sel 9 之外的对照（可选：同一 cap 连调两次，看 ID 是否递增）
//
//  判读：
//    · 某个 u32 字段随调用递增 → 那就是 ID
//    · 某个 u32 恒为 0/1 → 可能是状态码
//    · outSize 若是 0x10，说明只有 4 个 u32
//

#import <UIKit/UIKit.h>
#import <Metal/Metal.h>
#import <IOKit/IOKitLib.h>
#import <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <unistd.h>

static NSMutableString *gLog = nil;
static UITextView    *gView = nil;
static UILabel       *gStatus = nil;
static dispatch_queue_t gQ = nil;

static const char *kr_hint(uint32_t k)
{
    switch (k) {
        case 0:          return "SUCCESS";
        case 0xe00002bc: return "kIOReturnError";
        case 0xe00002be: return "kIOReturnNoResources";
        case 0xe00002c1: return "kIOReturnNotPrivileged";
        case 0xe00002c2: return "kIOReturnBadArgument";
        case 0xe00002c7: return "kIOReturnUnsupported";
        case 0xe00002cc: return "kIOReturnNotOpen";
        case 0xe00002e2: return "kIOReturnNotPermitted";
        default:         return "?";
    }
}

static void L(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    NSString *s = [NSString stringWithUTF8String:buf];
    if (!s) return;
    NSLog(@"AGXRES %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"agxres.log"];
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
            gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
        }
    });
}

// ---------------------------------------------------------------- Phase 1
static BOOL metal_warmup(void)
{
    L("=== Phase 1: Metal warmup ===");

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { L("  !! Metal unavailable"); return NO; }
    L("  device.name = %s", [[dev name] UTF8String] ?: "(null)");

    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) { L("  !! no command queue"); return NO; }

    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                                           width:16 height:16 mipmapped:NO];
    td.usage = MTLTextureUsageRenderTarget | MTLTextureUsageShaderRead;
    td.storageMode = MTLStorageModePrivate;

    id<MTLTexture> tex = [dev newTextureWithDescriptor:td];
    if (!tex) { L("  !! no texture"); return NO; }

    id<MTLCommandBuffer> cb = [q commandBuffer];
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture     = tex;
    rp.colorAttachments[0].loadAction  = MTLLoadActionClear;
    rp.colorAttachments[0].storeAction = MTLStoreActionStore;
    rp.colorAttachments[0].clearColor  = MTLClearColorMake(1.0, 0.0, 1.0, 1.0);
    id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rp];
    if (!enc) { L("  !! no encoder"); return NO; }
    [enc endEncoding];
    [cb commit];
    [cb waitUntilCompleted];

    BOOL ok = (cb.status == MTLCommandBufferStatusCompleted);
    L("  waitUntilCompleted -> %s", ok ? "Completed (GPU executed)" : "NOT completed");
    if (!ok && cb.error) L("  error = %s", [[cb.error description] UTF8String]);
    return ok;
}

// ---------------------------------------------------------------- Phase 3
static uint32_t g_lastIdCandidate = 0;

static void dump_out(const uint8_t *out, size_t os)
{
    size_t n = os > 0x40 ? 0x40 : os;
    char hexline[256]; int p = 0;
    for (size_t i = 0; i < n && p < 200; i++)
        p += snprintf(hexline + p, sizeof(hexline) - p, "%02x ", out[i]);
    L("            hex: %s", hexline);

    int nu32 = (int)(n / 4);
    char l32[256]; p = 0;
    for (int i = 0; i < nu32 && p < 220; i++)
        p += snprintf(l32 + p, sizeof(l32) - p, "[%d]=%u ", i, *(const uint32_t *)(out + i*4));
    if (nu32 > 0) L("            u32: %s", l32);

    int nu64 = (int)(n / 8);
    char l64[256]; p = 0;
    for (int i = 0; i < nu64 && p < 220; i++)
        p += snprintf(l64 + p, sizeof(l64) - p, "[%d]=0x%llx ", i,
                      (unsigned long long)*(const uint64_t *)(out + i*8));
    if (nu64 > 0) L("            u64: %s", l64);
}

static uint32_t try_new_resource_group(io_connect_t conn, uint32_t resType, uint32_t cap, const char *tag)
{
    uint8_t in[0x100];
    memset(in, 0, sizeof(in));
    *(uint32_t *)(in + 0x00) = resType;
    *(uint32_t *)(in + 0x38) = cap;

    uint8_t out[0x100];
    memset(out, 0, sizeof(out));
    size_t os = sizeof(out);

    kern_return_t kr = IOConnectCallStructMethod(conn, 9, in, sizeof(in), out, &os);
    L("  [%-6s] resType=0x%02x cap=0x%-4x -> 0x%08x %s  outSize=0x%zx",
      tag, resType, cap, (uint32_t)kr, kr_hint((uint32_t)kr), os);
    if (kr == KERN_SUCCESS && os > 0) {
        dump_out(out, os);
        // 记录第一个 u32 作为候选 ID
        if (os >= 4) g_lastIdCandidate = *(uint32_t *)out;
    }
    usleep(150 * 1000);
    return (kr == KERN_SUCCESS) ? *(uint32_t *)out : 0xffffffff;
}

static void run(void)
{
    L("===== p20: dump sel 9 output, locate resource-group ID =====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("");

    BOOL warmed = metal_warmup();
    if (!warmed) { L("!! warmup failed, results are baseline only"); }

    L("");
    L("=== Phase 2: open AGX client ===");
    CFMutableDictionaryRef m = IOServiceMatching("AGXAcceleratorG13P_B0");
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    if (svc == MACH_PORT_NULL) { L("  no service"); SetStatus(@"no service"); return; }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    L("  open(type=1) -> 0x%08x %s conn=0x%x", (uint32_t)kr, kr_hint((uint32_t)kr), conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { SetStatus(@"open fail"); return; }

    L("");
    L("=== Phase 3: sel 9 resType=3 x 5（看哪个字段随调用变化）===");

    // 关键：前两次用同一个 cap，看是否分配出两个不同 ID
    uint32_t id1 = try_new_resource_group(conn, 0x03, 0x80,  "1st");
    uint32_t id2 = try_new_resource_group(conn, 0x03, 0x80,  "2nd");
    uint32_t id3 = try_new_resource_group(conn, 0x03, 0x40,  "cap40");
    uint32_t id4 = try_new_resource_group(conn, 0x03, 0x100, "cap100");
    uint32_t id5 = try_new_resource_group(conn, 0x03, 0x200, "cap200");

    L("");
    L("=== Phase 4: 候选 ID 汇总（取输出第 1 个 u32）===");
    L("  1st(cap0x80)=%u  2nd(cap0x80)=%u  cap40=%u  cap100=%u  cap200=%u",
      id1, id2, id3, id4, id5);
    if (id1 != id2) L("  ** 同 cap 两次给出不同值 => 该字段是分配出来的 ID");
    else            L("  ** 同 cap 两次给出相同值 => 该字段不是 ID（可能是状态/版本）");

    L("");
    L("=== VERDICT ===");
    L("  · 找到随调用递增/变化的 u32 => 那就是 resource group ID");
    L("  · 下一步：用该 ID 组 type=3 命令，走 sel 26 提交");
    L("  · 若 outSize 只有 0x10 且四字段不变 => ID 可能不在输出里，需从别处取");

    SetStatus(@"done - see log");
    IOServiceClose(conn);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("agxres.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"agxres (p20)...";
    gStatus.textColor = [UIColor colorWithRed:0.4 green:0.9 blue:1.0 alpha:1];
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
