#include <jni.h>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "NativeCode"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C"
void native_ret(JNIEnv *env, jobject thiz, jint a) {
    char buffer[12];
    if (snprintf(buffer, sizeof(buffer), "%d", a) < 0) {
        LOGE("Failed to convert jint to string.");
        return;
    }

    std::string res = "Hello. Count is ";
    res += buffer;

    jstring jres = env->NewStringUTF(res.c_str());
    if (jres == nullptr) {
        LOGE("Failed to create jstring.");
        return;
    }

    jclass activityClass = env->GetObjectClass(thiz);
    if (activityClass == nullptr) {
        LOGE("Failed to find MainActivity class.");
        return;
    }

    // Get static method ID: getBoxId()
    jmethodID getBoxId = env->GetStaticMethodID(activityClass, "getBoxId", "()I");
    if (getBoxId == nullptr) {
        LOGE("Failed to find getBoxId() method.");
        return;
    }

    // Call getBoxId() to get R.id.box
    jint viewId = env->CallStaticIntMethod(activityClass, getBoxId);

    // Get findViewById method
    jmethodID findViewById = env->GetMethodID(activityClass, "findViewById", "(I)Landroid/view/View;");
    if (findViewById == nullptr) {
        LOGE("Failed to find findViewById(int) method.");
        return;
    }

    jobject textViewObj = env->CallObjectMethod(thiz, findViewById, viewId);
    if (textViewObj == nullptr) {
        LOGE("findViewById returned null.");
        return;
    }

    // Get TextView class
    jclass textViewClass = env->GetObjectClass(textViewObj);
    if (textViewClass == nullptr) {
        LOGE("Failed to get TextView class.");
        return;
    }

    // Get setText(CharSequence) method
    jmethodID setTextMethod = env->GetMethodID(textViewClass, "setText", "(Ljava/lang/CharSequence;)V");
    if (setTextMethod == nullptr) {
        LOGE("Failed to find setText(CharSequence) method.");
        return;
    }

    // Call setText with generated string
    env->CallVoidMethod(textViewObj, setTextMethod, jres);
    LOGI("TextView updated successfully with: %s", res.c_str());
}

static JNINativeMethod methods[] = {
        {"ret", "(I)V", (void*)native_ret}  // Java ret(int), returns void
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass clazz = env->FindClass("com/example/regnat/MainActivity");
    if (!clazz) {
        LOGE("Failed to find MainActivity class");
        return JNI_ERR;
    }

    if (env->RegisterNatives(clazz, methods, sizeof(methods) / sizeof(methods[0])) != 0) {
        LOGE("Failed to register native methods");
        return JNI_ERR;
    }

    return JNI_VERSION_1_6;
}