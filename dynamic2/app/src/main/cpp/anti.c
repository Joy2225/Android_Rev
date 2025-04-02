//
// Created by Joy on 3/20/2025.
//
#include <stdlib.h>     // exit()
#include <signal.h>     // sigtrap handling
#include <sys/wait.h>   // waitpid
#include <unistd.h>     // fork(), sleep()
#include <jni.h>
#include <android/log.h> // Logging for Android

#define LOG_TAG "AntiEmulator"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void handler_sigtrap(int signo) {
    exit(-1);
}

void handler_sigbus(int signo) {
    exit(-1);
}

void setupSigTrap() {
    signal(SIGTRAP, handler_sigtrap);
    signal(SIGBUS, handler_sigbus);
}

void tryBKPT() {
#if defined(__arm__)
    __asm__ __volatile__ ("bkpt 255");
#endif
}

JNIEXPORT jint JNICALL Java_com_example_dynamic_MainActivity_qemuBkpt(JNIEnv* env, jobject jObject) {

    pid_t child = fork();
    int child_status, status = 0;

    if(child == 0) {
        setupSigTrap();
        tryBKPT();
    } else if(child == -1) {
        LOGE("Fork failed!");
        status = -1;
    } else {
        int timeout = 0;
        int i = 0;

        while (waitpid(child, &child_status, WNOHANG) == 0) {
            sleep(1);
            if(i++ == 1) {
                timeout = 1;
                break;
            }
        }

        if (timeout == 1) {
            LOGI("Timeout: Emulator detected.");
            status = 1;
        }

        if (WIFEXITED(child_status)) {
            LOGI("Exited normally: Likely a real device.");
            status = 0;
        } else {
            LOGI("Abnormal exit: Emulator detected.");
            status = 2;
        }

        kill(child, SIGKILL);
    }

    return status;
}
