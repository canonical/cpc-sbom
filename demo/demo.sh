#!/bin/bash -eux
# Download the current Ubuntu 22.04 cloud image and generate an SPDX SBOM for it.
CLOUD_IMAGE_ARCHITECTURE="amd64" # amd64, arm64, armhf, ppc64el, riscv64 and s390x are all valid values
CLOUD_IMAGE="ubuntu-22.04-server-cloudimg-${CLOUD_IMAGE_ARCHITECTURE}.img"
DOCUMENT_NAME="ubuntu-22.04-server-cloudimg-${CLOUD_IMAGE_ARCHITECTURE}"
CLOUD_IMAGE_SPDX="${CLOUD_IMAGE}.spdx"
CLOUD_IMAGE_SPDX_GENERATION_LOG="${CLOUD_IMAGE}.spdx.log"

CLOUD_IMAGE_SPDX_INCLUDING_INSTALLED_FILES="${CLOUD_IMAGE}_installed_files.spdx"
CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES="${CLOUD_IMAGE}_installed_files.spdx.log"

# download a recent ubuntu cloud image
if [ ! -f ${CLOUD_IMAGE} ]; then
    wget http://cloud-images.ubuntu.com/releases/jammy/release/${CLOUD_IMAGE} -O ${CLOUD_IMAGE}
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
rm --force ${CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES} ${CLOUD_IMAGE_SPDX_INCLUDING_INSTALLED_FILES}

CPC_SBOM_SCRIPT_PATH=$(which cpc-sbom)

# generate the SPDX document and redirect any warning or errors to a log file
# By using `--update-apt-cache --rootdir-architecture` we ensure there is a populated apt cache in
# the cloud image filesystem before generating the SBOM
sudo ${CPC_SBOM_SCRIPT_PATH} --update-apt-cache --rootdir-architecture ${CLOUD_IMAGE_ARCHITECTURE} --ignore-copyright-parsing-errors --ignore-copyright-file-not-found-errors --rootdir ./ubuntu-cloud-image-mnt --document-name ${DOCUMENT_NAME} > "${CLOUD_IMAGE_SPDX}" 2> "${CLOUD_IMAGE_SPDX_GENERATION_LOG}" && echo "SBOM generation successfull" || echo "SBOM generation generated warnings or errors. See '${CLOUD_IMAGE_SPDX_GENERATION_LOG}' for details"

# generate the SPDX document including installed files and redirect any warning or errors to a log file
# generate as sudo so that the checksum generation can be done as root for files that are not readable by non root user
CPC_SBOM_SCRIPT_PATH=$(which cpc-sbom)
sudo ${CPC_SBOM_SCRIPT_PATH} --update-apt-cache --rootdir-architecture ${CLOUD_IMAGE_ARCHITECTURE} --ignore-copyright-parsing-errors --ignore-copyright-file-not-found-errors --include-installed-files --rootdir ./ubuntu-cloud-image-mnt --document-name ${DOCUMENT_NAME} > "${CLOUD_IMAGE_SPDX_INCLUDING_INSTALLED_FILES}" 2> "${CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES}" && echo "SBOM including installed files generation successfull" || echo "SBOM including installed files generation generated warnings or errors. See '${CLOUD_IMAGE_SPDX_GENERATION_LOG}' for details"

# unmount the cloud image
sudo umount ${ABS_MOUNT_PATH}
sudo kpartx -d -v "/dev/${DEVICE_TO_CONNECT}"
sudo qemu-nbd --disconnect "/dev/${DEVICE_TO_CONNECT}"
sudo rm --recursive --verbose --force ${ABS_MOUNT_PATH}

## delete the cloud image
rm  --verbose --force ${CLOUD_IMAGE}