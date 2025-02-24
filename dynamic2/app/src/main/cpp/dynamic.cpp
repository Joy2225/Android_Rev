//#include <jni.h>
//#include <string>
//#include <unistd.h>
//#include <sys/stat.h>
//#include <fstream>
//#include <dlfcn.h>
//#include <android/log.h>
//#include <stdlib.h>
//#include <stdio.h>
//
//#define LOG_TAG "RootDetection"
//#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
//#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
//
//void crashApp() {
//    LOGE("Security violation detected! Crashing app.");
//    abort();
//}
//
//bool isRooted() {
//    const char* paths[] = {
//            "/system/app/Superuser.apk",
//            "/sbin/su",
//            "/system/bin/su",
//            "/system/xbin/su",
//            "/data/local/xbin/su",
//            "/data/local/bin/su",
//            "/system/sd/xbin/su",
//            "/system/bin/failsafe/su",
//            "/data/local/su",
//            "/su/bin/su",
//            "/system/xbin/busybox"
//    };
//
//    for (const char* path : paths) {
//        if (access(path, F_OK) == 0) {
//            LOGE("Root path found: %s", path);
//            crashApp();
//            return true;
//        }
//        FILE* file = fopen(path, "r");
//        if (file) {
//            fclose(file);
//            LOGE("Root file found using fopen: %s", path);
//            crashApp();
//            return true;
//        }
//    }
//
//    std::ifstream buildProps("/system/build.prop");
//    if (buildProps.is_open()) {
//        std::string line;
//        while (std::getline(buildProps, line)) {
//            if (line.find("test-keys") != std::string::npos) {
//                LOGE("Test-keys found in build.prop");
//                crashApp();
//                return true;
//            }
//        }
//        buildProps.close();
//    }
//
//    const char* apps[] = {
//            "com.noshufou.android.su",
//            "com.thirdparty.superuser",
//            "eu.chainfire.supersu",
//            "com.koushikdutta.superuser"
//    };
//    for (const char* app : apps) {
//        std::string cmd = "pm path ";
//        cmd += app;
//        FILE* pipe = popen(cmd.c_str(), "r");
//        if (pipe != nullptr) {
//            char buffer[128];
//            std::string result = "";
//            while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
//                result += buffer;
//            }
//            pclose(pipe);
//            if (!result.empty()) {
//                LOGE("Root app found: %s", app);
//                crashApp();
//                return true;
//            }
//        }
//    }
//
//    LOGI("No root indicators found.");
//    return false;
//}
//
//bool detectFrida() {
//    void* handle = dlopen("libfrida-gadget.so", RTLD_NOW);
//    if (handle) {
//        LOGE("Frida detected: libfrida-gadget.so loaded");
//        dlclose(handle);
//        crashApp();
//        return true;
//    }
//    return false;
//}
//
//static bool is_rooted_global = false;
//static bool is_frida_detected = false;
//
//JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
//    JNIEnv* env;
//    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
//        return JNI_ERR;
//    }
//
//    LOGI("JNI_OnLoad called");
//    is_rooted_global = isRooted();
//    is_frida_detected = detectFrida();
//
//    return JNI_VERSION_1_6;
//}
//
//extern "C" JNIEXPORT jboolean JNICALL
//Java_com_example_dynamic_MainActivity_isDeviceRooted(JNIEnv* env, jobject /* this */) {
//    return static_cast<jboolean>(is_rooted_global);
//}
//
//extern "C" JNIEXPORT jboolean JNICALL
//Java_com_example_dynamic_MainActivity_isFridaDetected(JNIEnv* env, jobject /* this */) {
//    return static_cast<jboolean>(is_frida_detected);
//}

#include <jni.h>
#include <string>
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <dlfcn.h>
#include <android/log.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <sstream>

#define LOG_TAG "RootDetection"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void crashApp() {
    LOGE("Security violation detected! Crashing app.");
    abort();
}

bool checkFileStat(const char* path) {
    struct stat fileattrib;
    if (stat(path, &fileattrib) == 0) {
        LOGE("Root path found: %s", path);
        return true;
    }
    return false;
}

bool isRooted() {
    const char* paths[] = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/xbin/busybox",
            "/dev/.magisk.unblock",
            "/sbin/magiskinit",
            "/sbin/magisk",
            "/sbin/.magisk",
            "/data/adb/magisk.img",
            "/data/adb/magisk.db",
            "/data/adb/.boot_count",
            "/data/adb/magisk_simple",
            "/data/adb/magisk",
            "/cache/.disable_magisk",
            "/cache/magisk.log",
            "/init.magisk.rc"
    };

    for (const char* path : paths) {
        if (checkFileStat(path)) {
            crashApp();
            return true;
        }
    }

    char* envPath = getenv("PATH");
    if (envPath) {
        std::istringstream ss(envPath);
        std::string dir;
        while (std::getline(ss, dir, ':')) {
            std::string suPath = dir + "/su";
            if (checkFileStat(suPath.c_str())) {
                crashApp();
                return true;
            }
        }
    }

    std::ifstream buildProps("/system/build.prop");
    if (buildProps.is_open()) {
        std::string line;
        while (std::getline(buildProps, line)) {
            if (line.find("test-keys") != std::string::npos) {
                LOGE("Test-keys found in build.prop");
                crashApp();
                return true;
            }
        }
        buildProps.close();
    }

    LOGI("No root indicators found.");
    return false;
}

bool detectFrida() {
    void* handle = dlopen("libfrida-gadget.so", RTLD_NOW);
    if (handle) {
        LOGE("Frida detected: libfrida-gadget.so loaded");
        dlclose(handle);
        crashApp();
        return true;
    }
    return false;
}

static bool is_rooted_global = false;
static bool is_frida_detected = false;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad called");


    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_dynamic_MainActivity_isDeviceRooted(JNIEnv* env, jobject /* this */) {
    return static_cast<jboolean>(is_rooted_global);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_dynamic_MainActivity_isFridaDetected(JNIEnv* env, jobject /* this */) {
    return static_cast<jboolean>(is_frida_detected);
}
