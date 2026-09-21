#!/bin/sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
/usr/bin/busybox --install -s /usr/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
set -e
uname -a
mkdir -p /work
mount -t tmpfs tmpfs /work
cd /work
echo ARTIFACT_STORE_TMPFS_START
/artifact-store-tests
echo ARTIFACT_STORE_TMPFS_PASS
cd /
umount /work
modprobe virtio_pci
modprobe virtio_blk
modprobe ext4
mke2fs -t ext4 -F /dev/vda
mount -t ext4 /dev/vda /work
cd /work
echo ARTIFACT_STORE_EXT4_START
/artifact-store-tests
echo ARTIFACT_STORE_EXT4_PASS
sync
cd /
umount /work
echo ARTIFACT_STORE_LINUX_COMPLETE
poweroff -f
