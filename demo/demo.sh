#!/bin/bash -eux
# Download the current Ubuntu 22.04 cloud image and generate an SPDX SBOM for it.
CLOUD_IMAGE="ubuntu-22.04-server-cloudimg-amd64.img"
CLOUD_IMAGE_SPDX="${CLOUD_IMAGE}.spdx"
CLOUD_IMAGE_SPDX_GENERATION_LOG="${CLOUD_IMAGE}.spdx.log"

# download a recent ubuntu cloud image
if [ ! -f ${CLOUD_IMAGE} ]; then
    wget http://cloud-images.ubuntu.com/releases/jammy/release/ubuntu-22.04-server-cloudimg-amd64.img -O ${CLOUD_IMAGE}
fi

# mount the cloud image
DEVICE_TO_CONNECT="nbd0"
MOUNTPOINT="./ubuntu-cloud-image-mnt"
ABS_MOUNT_PATH=$(realpath ${MOUNTPOINT})
mkdir --parents ${ABS_MOUNT_PATH}
sudo modprobe nbd
sudo qemu-nbd --connect "/dev/${DEVICE_TO_CONNECT}" ${CLOUD_IMAGE}
sudo kpartx -a -v "/dev/${DEVICE_TO_CONNECT}"
sudo mount /dev/mapper/${DEVICE_TO_CONNECT}p1 ${ABS_MOUNT_PATH}

# delete any previous SPDX generation log or SPDX file
rm --force ${CLOUD_IMAGE_SPDX_GENERATION_LOG} ${CLOUD_IMAGE_SPDX}

# generate the SPDX document and redirect any warning or errors to a log file
cpc-sbom --ignore-copyright-parsing-errors --ignore-copyright-file-not-found-errors --include-installed-files --rootdir ./ubuntu-cloud-image-mnt > "${CLOUD_IMAGE_SPDX}" 2> "${CLOUD_IMAGE_SPDX_GENERATION_LOG}" && echo "SBOM generation successfull" || echo "SBOM generation generated warnings or errors. See '${CLOUD_IMAGE_SPDX_GENERATION_LOG}' for details"

# unmount the cloud image
sudo umount ${ABS_MOUNT_PATH}
sudo kpartx -d -v "/dev/${DEVICE_TO_CONNECT}"
sudo qemu-nbd --disconnect "/dev/${DEVICE_TO_CONNECT}"
sudo rm --recursive --verbose --force ${ABS_MOUNT_PATH}

# delete the cloud image
# rm  --verbose --force ${CLOUD_IMAGE}