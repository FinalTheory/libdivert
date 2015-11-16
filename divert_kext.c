#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/kext/KextManager.h>
#include "KernFunc.h"


int divert_load_kext(char *kext_path) {
    if (strstr(kext_path, KEXT_FILE_NAME) == NULL) {
        char *real_path = malloc(strlen(kext_path) +
                                 strlen(KEXT_FILE_NAME) + 2);
        strcpy(real_path, kext_path);
        if (kext_path[strlen(kext_path) - 1] != '/') {
            strcat(real_path, "/");
        }
        strcat(real_path, KEXT_FILE_NAME);
        kext_path = real_path;
    }

    // Use KextManager to load kernel extension
    CFStringRef km_path;
    CFURLRef km_url;
    km_path = CFStringCreateWithCString(kCFAllocatorDefault, kext_path,
                                        kCFStringEncodingUTF8);
    km_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, km_path,
                                           kCFURLPOSIXPathStyle, true);
    int result = KextManagerLoadKextWithURL(km_url, NULL);

    CFRelease(km_path);
    CFRelease(km_url);
    return result;
}


int divert_unload_kext() {
    // Use KextManager to unload kernel extension
    return KextManagerUnloadKextWithIdentifier(CFSTR(KEXT_CTL_NAME));
}
