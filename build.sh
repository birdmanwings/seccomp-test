# 这里自己配置好 NDK 目录
"$ANDROID_NDK_ROOT_21"/ndk-build NDK_PROJECT_PATH=./ APP_BUILD_SCRIPT=./Android.mk NDK_APPLICATION_MK=./Application.mk NDK_DEBUG=0
adb push libs/arm64-v8a/seccomp_example /data/local/tmp
adb shell chmod 777  /data/local/tmp/seccomp_example