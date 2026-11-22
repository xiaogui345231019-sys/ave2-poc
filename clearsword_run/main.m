// ClearSword on-device runner.
// Keeps clearsword_run() untouched; replaces binary.c's plain main() with a
// UIWindow + stderr capture so the exploit's own LOG() lines are visible on screen
// (the device has no shell, and syslog capture is unreliable over USB).

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "clearsword/poc.h"

static UITextView *g_logView = nil;
static NSMutableString *g_log = nil;
static int g_pipefd[2] = { -1, -1 };
static FILE *g_logfp = NULL;

static void append_line(NSString *s)
{
    // Write to a file in Documents as well, because the process gets killed by the
    // CPU policy long before it finishes and the UI text dies with it.
    // (Do NOT also NSLog here: NSLog writes to stderr, which we have dup2'd into the
    //  pipe below -> infinite recursion. That bug once produced a 785 MB log.)
    if (g_logfp) {
        fputs([s UTF8String], g_logfp);
        fflush(g_logfp);
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        [g_log appendString:s];
        // keep the buffer bounded
        if (g_log.length > 200000) {
            [g_log deleteCharactersInRange:NSMakeRange(0, g_log.length - 150000)];
        }
        g_logView.text = g_log;
        NSRange r = NSMakeRange(g_logView.text.length, 0);
        [g_logView scrollRangeToVisible:r];
    });
}

// drain the stderr pipe into the UI
static void *pipe_reader(void *arg)
{
    char buf[1024];
    for (;;) {
        ssize_t n = read(g_pipefd[0], buf, sizeof(buf) - 1);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            break;
        }
        buf[n] = 0;
        append_line([NSString stringWithUTF8String:buf]);
    }
    return NULL;
}

static void start_stderr_capture(void)
{
    if (pipe(g_pipefd) != 0) return;
    dup2(g_pipefd[1], STDERR_FILENO);
    dup2(g_pipefd[1], STDOUT_FILENO);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    pthread_t th;
    pthread_create(&th, NULL, pipe_reader, NULL);
    pthread_detach(th);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate

- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)opts
{
    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor blackColor];

    g_log = [NSMutableString string];
    g_logView = [[UITextView alloc] initWithFrame:vc.view.bounds];
    g_logView.backgroundColor = [UIColor blackColor];
    g_logView.textColor = [UIColor colorWithRed:0.4 green:1.0 blue:0.4 alpha:1.0];
    g_logView.font = [UIFont fontWithName:@"Menlo" size:10];
    g_logView.editable = NO;
    g_logView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [vc.view addSubview:g_logView];

    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];

    // persistent log file (survives the process being killed)
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    NSString *logPath = [docs stringByAppendingPathComponent:@"cs.log"];
    g_logfp = fopen([logPath UTF8String], "w");

    start_stderr_capture();

    append_line([NSString stringWithFormat:@"=== ClearSword runner ===\n"
                 @"device iOS %@\n"
                 @"NOTE: this is CVE-2025-43520 (cluster_write_contig race)\n"
                 @"if the race is patched on this build, expect a clean failure\n\n",
                 [[UIDevice currentDevice] systemVersion]]);

    // run the exploit off the main thread so the UI keeps updating
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @autoreleasepool {
            int rc = clearsword_run();
            append_line([NSString stringWithFormat:@"\n=== clearsword_run() returned %d ===\n", rc]);
        }
    });

    return YES;
}

@end

int main(int argc, char *argv[])
{
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class]));
    }
}
