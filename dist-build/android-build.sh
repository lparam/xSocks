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

export PREFIX="$(pwd)/xsocks-android-${TARGET_ARCH}"
export TOOLCHAIN_DIR="$(pwd)/android-toolchain-${TARGET_ARCH}"
export PATH="${PATH}:${TOOLCHAIN_DIR}/bin"

rm -rf "${TOOLCHAIN_DIR}" "${PREFIX}"

bash $MAKE_TOOLCHAIN \
    --arch=$ARCH \
    --install-dir=$TOOLCHAIN_DIR \
    --platform=android-9

make distclean
make V=1 CROSS="${HOST_COMPILER}-" libuv libsodium xsocks xforwarder
mkdir -p $PREFIX
cp -a xsocks xforwarder $PREFIX
${HOST_COMPILER}-strip --strip-unneeded $PREFIX/xsocks
${HOST_COMPILER}-strip --strip-unneeded $PREFIX/xforwarder
echo "xsocks has been installed into $PREFIX"
