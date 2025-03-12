#include <jni.h>
#include <string>
#include <dlfcn.h>
#include <android/log.h>
#include <stdlib.h>
#include <unistd.h>

#define LOG_TAG "RootDetection"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void crashApp(JNIEnv* env, jobject activity) {
    jclass activityClass = env->GetObjectClass(activity);
    jmethodID finishMethod = env->GetMethodID(activityClass, "finish", "()V");
    if (finishMethod) {
        env->CallVoidMethod(activity, finishMethod);
    }

    // Forcefully kill process
    LOGE("Forcefully terminating process");
    abort();  // This will SIGABRT the process, ensuring it doesn't restart.
}


// Frida detection by checking for the Frida Gadget shared library
bool detectFrida() {
    void* handle = dlopen("libfrida-gadget.so", RTLD_NOW);
    if (handle) {
        LOGE("Frida detected: libfrida-gadget.so loaded");
        dlclose(handle);
        return true;
    }
    return false;
}

// Root detection function mimicking Java logic
bool checkRootViaPath() {
    const char* envPath = getenv("PATH");
    if (envPath) {
        char* path = strdup(envPath);
        char* token = strtok(path, ":");
        while (token) {
            std::string suPath = std::string(token) + "/su";
            if (access(suPath.c_str(), F_OK) == 0) {
                LOGE("Root detected via PATH: %s", suPath.c_str());
                free(path);
                return true;
            }
            token = strtok(nullptr, ":");
        }
        free(path);
    }
    return false;
}

bool checkRootBuildTags() {
    FILE* file = fopen("/system/build.prop", "r");
    if (!file) return false;

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "test-keys")) {
            LOGE("Root detected via test-keys in build.prop!");
            fclose(file);
            return true;
        }
    }
    fclose(file);
    return false;
}

bool checkRootFiles() {
    const char* rootFiles[] = {
            "/system/app/Superuser.apk",
            "/system/xbin/daemonsu",
            "/system/etc/init.d/99SuperSUDaemon",
            "/system/bin/.ext/.su",
            "/system/etc/.has_su_daemon",
            "/system/etc/.installed_su_daemon",
            "/dev/com.koushikdutta.superuser.daemon/",
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

    for (const char* path : rootFiles) {
        if (access(path, F_OK) == 0) {
            LOGE("Root file detected: %s", path);
            return true;
        }
    }
    return false;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad called");

    // Get the current Activity instance
    jclass activityThreadClass = env->FindClass("android/app/ActivityThread");
    jmethodID currentActivityThreadMethod = env->GetStaticMethodID(activityThreadClass, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject activityThread = env->CallStaticObjectMethod(activityThreadClass, currentActivityThreadMethod);

    jmethodID getApplicationMethod = env->GetMethodID(activityThreadClass, "getApplication", "()Landroid/app/Application;");
    jobject appContext = env->CallObjectMethod(activityThread, getApplicationMethod);

    if (appContext == nullptr) {
        LOGE("Failed to get application context. JNI_OnLoad will continue.");
        return JNI_VERSION_1_6;
    }

    jclass appClass = env->GetObjectClass(appContext);
    jmethodID getActivityMethod = env->GetMethodID(appClass, "getApplicationContext", "()Landroid/content/Context;");
    jobject activity = env->CallObjectMethod(appContext, getActivityMethod);

    if (activity == nullptr) {
        LOGE("Failed to get activity context.");
        return JNI_VERSION_1_6;
    }

    // Perform root checks
    if (checkRootViaPath()) {
        LOGE("Root detected via PATH search in JNI_OnLoad!");
        crashApp(env, activity);
    }

    if (checkRootBuildTags()) {
        LOGE("Root detected via test-keys in JNI_OnLoad!");
        crashApp(env, activity);
    }

    if (checkRootFiles()) {
        LOGE("Root file detected in JNI_OnLoad!");
        crashApp(env, activity);
    }

    // Check for Frida
    if (detectFrida()) {
        LOGE("Frida detected in JNI_OnLoad!");
        crashApp(env, activity);
    }

    return JNI_VERSION_1_6;
}
