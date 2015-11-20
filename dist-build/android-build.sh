#! /bin/sh

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "You should probably set ANDROID_NDK_HOME to the directory containing"
    echo "the Android NDK"
    exit
fi

if [ "x$TARGET_ARCH" = 'x' ] || [ "x$ARCH" = 'x' ] || [ "x$HOST_COMPILER" = 'x' ]; then
    echo "You shouldn't use android-build.sh directly, use android-[arch].sh instead"
    exit 1
fi

export MAKE_TOOLCHAIN="${ANDROID_NDK_HOME}/build/tools/make-standalone-toolchain.sh"
export TOOLCHAIN_DIR="$(pwd)/android-toolchain-${TARGET_ARCH}"
export PREFIX="$(pwd)/xSocks-android-${TARGET_ARCH}"
export PATH="${PATH}:${TOOLCHAIN_DIR}/bin"

if [ ! -d $TOOLCHAIN_DIR ]; then
    bash $MAKE_TOOLCHAIN \
        --arch=$ARCH \
        --install-dir=$TOOLCHAIN_DIR \
        --platform=android-9
fi

make CROSS="${HOST_COMPILER}-" O="${PREFIX}" android
${HOST_COMPILER}-strip --strip-unneeded $PREFIX/xSocks
${HOST_COMPILER}-strip --strip-unneeded $PREFIX/xForwarder
echo "xSocks has been installed into $PREFIX"
