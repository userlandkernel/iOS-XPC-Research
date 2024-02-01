/*
 * This is the code for interaction with the XPC Services
*/
#include <stdbool.h>
#define CALCULATOR_PATH_IOS16  "/var/containers/Bundle/Application/C83EAD61-5BDD-483A-89DF-A01FAA2D6A8D/Calculator.app/Calculator"
bool NEHelperLauncher(const char *exePath, const char* bundleId);
bool RunningBoardLauncher(const char* exePath, const char* bundleId,const char* jobLabel, const char* stdoutPath, const char*stderrPath, const char** environ, const char* reason);
