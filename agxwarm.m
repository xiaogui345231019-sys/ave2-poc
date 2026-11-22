//
//  agxwarm.m — p19：Metal 预热 + resType=3（IOGPU A 侧最后的机会）
//
//  依据（2026-11-22 完整链路）：
//    sel 9 resType=3
//      → IOGPU*->vtable[0x5b0]   wrapper 0x9c1b714
//        → AGX*->vtable[0x650]   alloc thunk 0x86f0690
//          → AGXResource::alloc  0x877ddb0                  ✅ 成功
//        → AGXResource*->vtable[0x80]  0x877dc30
//          → accelerator->vtable[0x90]                      ❌ bit0=1
//        → free，返回 NULL
//      → Error
//
//  关键：accelerator 是【全局单例】
//    0x877dc48  ldr x8, [x8, #0xc60]     ← 从全局取，不是 per-client
//  ⇒ Metal 预热的是同一个实例，状态能传递给我门的 AGX client
//
//  本包做三阶段：
//    Phase 1  Metal 预热：MTLDevice → CommandQueue → Texture → blit fill → commit → ★waitUntilCompleted
//    Phase 2  IOServiceOpen(AGXAcceleratorG13P_B0, type=1)
//    Phase 3  ★EARLY sel 9 resType=3 cap=0x80（进程内第一次，排除状态污染）
//
//  判据（唯一）：[EARLY] 0x03 cap=0x80 -> 0x00000000 SUCCESS
//
//  风险：极低。Metal 是公开 API，blit fill 1 张 16x16 texture。
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
    NSLog(@"AGXWARM %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"agxwarm.log"];
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
// 返回 YES 表示 GPU 真的跑完了一次工作
static BOOL metal_warmup(void)
{
    L(@"=== Phase 1: Metal 预热 ===");

    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    L(@"  MTLCreateSystemDefaultDevice -> %s", dev ? "OK" : "nil");
    if (!dev) { L(@"  ★ Metal 不可用，Phase 1 失败"); return NO; }
    L(@"  device.name = %s", [[dev name] UTF8String] ?: "(null)");

    id<MTLCommandQueue> q = [dev newCommandQueue];
    L(@"  newCommandQueue -> %s", q ? "OK" : "nil");
    if (!q) return NO;

    // 16x16 RGBA8 texture，不需要 shader
    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                                           width:16
                                                          height:16
                                                       mipmapped:NO];
    td.usage = MTLTextureUsageShaderRead | MTLTextureUsageShaderWrite;
    td.storageMode = MTLStorageModePrivate;

    id<MTLTexture> tex = [dev newTextureWithDescriptor:td];
    L(@"  newTextureWithDescriptor(16x16 RGBA8, private) -> %s", tex ? "OK" : "nil");
    if (!tex) return NO;

    id<MTLCommandBuffer> cb = [q commandBuffer];
    id<MTLBlitCommandEncoder> blit = [cb blitCommandEncoder];
    L(@"  blitCommandEncoder -> %s", blit ? "OK" : "nil");
    if (!blit) return NO;

    // fillTexture 不需要 shader / metallib
    [blit fillTexture:tex
            withColor:MTLClearColorMake(1.0, 0.0, 1.0, 1.0)
                 level:0
                  slice:0];
    [blit endEncoding];

    [cb commit];
    L(@"  commit 完成，等 GPU ...");

    // ★★★ 这一行是关键：必须等 GPU 真正跑完，accelerator 才会进入就绪态
    [cb waitUntilCompleted];

    if (cb.status == MTLCommandBufferStatusCompleted) {
        L(@"  ★ waitUntilCompleted -> Completed ✓ GPU 已执行");
        return YES;
    }
    L(@"  ★ waitUntilCompleted -> status=%ld（GPU 未正常完成）", (long)cb.status);
    if (cb.error) L(@"    error = %s", [[cb.error description] UTF8String]);
    return NO;
}

// ---------------------------------------------------------------- Phase 3
// EARLY: 进程内第一次 resType=3 调用
static void try_new_resource_group(io_connect_t conn, uint32_t resType, uint32_t cap, const char *tag)
{
    // 输入结构：resType 在最前，capacity 在 +0x38（依据 p18 扫描时的排布）
    uint8_t in[0x100];
    memset(in, 0, sizeof(in));
    *(uint32_t *)(in + 0x00) = resType;
    *(uint32_t *)(in + 0x38) = cap;

    uint8_t out[0x100];
    memset(out, 0, sizeof(out));
    size_t os = sizeof(out);

    kern_return_t kr = IOConnectCallStructMethod(conn, 9, in, sizeof(in), out, &os);
    L(@"  [%-6s] resType=0x%02x cap=0x%-4x -> 0x%08x  %s",
      tag, resType, cap, (uint32_t)kr, kr_hint((uint32_t)kr));
    usleep(150 * 1000);
}

static void run(void)
{
    L(@"===== p19: Metal 预热 + resType=3 =====");
    L(@"uid=%d pid=%d", getuid(), getpid());
    L(@"链路: sel9 → +0x5b0 → +0x650(alloc) → AGXResource::+0x80 → accelerator->vtable[0x90]");
    L(@"");

    // ---- Phase 1 ----
    BOOL warmed = metal_warmup();

    L(@"");
    L(@"=== Phase 2: 打开 AGX client ===");
    CFMutableDictionaryRef m = IOServiceMatching("AGXAcceleratorG13P_B0");
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    L(@"  service = 0x%x", svc);
    if (svc == MACH_PORT_NULL) { SetStatus(@"无服务"); return; }

    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    L(@"  open(type=1) -> 0x%08x %s conn=0x%x", (uint32_t)kr, kr_hint((uint32_t)kr), conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { SetStatus(@"打不开"); return; }

    // ---- Phase 3：EARLY，必须第一件事 ----
    L(@"");
    L(@"=== Phase 3: ★EARLY sel 9 resType=3（进程内第一次）===");
    if (warmed) L(@"  （Metal 已预热，accelerator 应为就绪态）");
    else        L(@"  （★ Metal 预热失败，本次结果只能作为基线）");

    try_new_resource_group(conn, 0x03, 0x80,  "EARLY");
    // 对照组：其他三档（p18 已证全 Error，这里确认预热是否改变其中任意一档）
    try_new_resource_group(conn, 0x03, 0x40,  "A");
    try_new_resource_group(conn, 0x03, 0x100, "B");
    try_new_resource_group(conn, 0x03, 0x200, "C");

    L(@"");
    L(@"=== 判读 ===");
    L(@"  [EARLY] 0x03 cap=0x80 -> 0x00000000 SUCCESS  => ★★★ A 侧复活，立刻做 type=3 命令");
    L(@"  [EARLY] 仍是 0xe00002bc Error              => Metal 预热不足以驱动 accelerator->vtable[0x90]");
    L(@"                                               => 下一步：解 [0x7ad9c60]+0x90 的目标函数，看它检查什么");
    L(@"  [EARLY] 变成其他码                          => 状态变了，记录并扩展");

    SetStatus(warmed ? @"完成（已预热）" : @"完成（预热失败）");
    IOServiceClose(conn);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (strong, nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    if (!gLog) gLog = [NSMutableString new];
    if (!gQ) gQ = dispatch_queue_create("agxwarm.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"agxwarm (p19)...";
    gStatus.textColor = [UIColor colorWithRed:0.4 green:0.9 blue:1.0 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 84, self.window.bounds.size.width, h - 84)];
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
