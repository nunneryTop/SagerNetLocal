#!/bin/sh

set -ex

eval "$OPENWRT_FLAGS"

sysroot=$PWD/out/sysroot-build/openwrt/$release/$arch
if [ -d $sysroot/lib ]; then
  exit 0
fi
mkdir -p $sysroot

case "$arch" in
arm_*) abi=musl_eabi;;
*) abi=musl;;
esac

if [ "$subtarget" ]; then
  SDK_PATH=openwrt-sdk-$release-$target-${subtarget}_gcc-${gcc_ver}_${abi}.Linux-x86_64
else
  subtarget='generic'
  SDK_PATH=openwrt-sdk-$release-${target}_gcc-${gcc_ver}_${abi}.Linux-x86_64
fi
SDK_URL=https://downloads.openwrt.org/releases/$release/targets/$target/$subtarget/$SDK_PATH.tar.xz
rm -rf $SDK_PATH
curl $SDK_URL | tar xJf -
cd $SDK_PATH
full_root=staging_dir/toolchain-*_gcc-${gcc_ver}_${abi}
cat >include.txt <<EOF
./include
./lib/*.o
./lib/gcc/*/libgcc.a
./lib/gcc/*/libgcc_eh.a
./lib/libatomic.so*
./lib/libatomic.a
./lib/libc.so
./lib/libc.a
./lib/libdl.a
./lib/ld-*
./lib/libgcc_s.*
./lib/libm.a
./lib/libpthread.a
./lib/libresolv.a
./lib/librt.a
./usr
*.ld.bin
EOF
tar cf - -C $full_root --hard-dereference . | tar xf - -C $sysroot --wildcards --wildcards-match-slash -T include.txt
rm -rf include.txt $SDK_PATH
cd $sysroot/*-openwrt-linux-musl*/bin
case "$arch" in
mips*) mv .ld.bin ld;;
*) rm .ld.bin;;
esac
