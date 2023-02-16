#!/bin/bash -eux
# Download the current Ubuntu 22.04 cloud image and generate an SPDX SBOM for it.
CLOUD_IMAGE="ubuntu-lunar-oci-s390x-root.tar.gz"
CLOUD_IMAGE_SPDX="${CLOUD_IMAGE}.spdx"
CLOUD_IMAGE_SPDX_GENERATION_LOG="${CLOUD_IMAGE}.spdx.log"

CLOUD_IMAGE_SPDX_INCLUDING_INSTALLED_FILES="${CLOUD_IMAGE}_installed_files.spdx"
CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES="${CLOUD_IMAGE}_installed_files.spdx.log"

# download a recent ubuntu cloud image
if [ ! -f ${CLOUD_IMAGE} ]; then
    wget https://partner-images.canonical.com/oci/lunar/current/${CLOUD_IMAGE} -O ${CLOUD_IMAGE}
fi

MOUNTPOINT="./ubuntu-cloud-image-mnt"
ABS_MOUNT_PATH=$(realpath ${MOUNTPOINT})
mkdir --parents ${ABS_MOUNT_PATH}

rm --force ${CLOUD_IMAGE_SPDX_GENERATION_LOG} ${CLOUD_IMAGE_SPDX}

# permit to keep the permission for the /tmp/ folder

sudo tar --same-owner -xf ${CLOUD_IMAGE} -C ${ABS_MOUNT_PATH}

# ensure there is a populated apt cache in the cloud image filesystem before generating the SBOM
sudo mv "${ABS_MOUNT_PATH}/etc/resolv.conf" "${ABS_MOUNT_PATH}/etc/resolv.bak"
sudo cp --verbose "/etc/resolv.conf" "${ABS_MOUNT_PATH}/etc/resolv.conf"

# permit to create /dev/null because it's don't exist for oci image.
sudo mknod -m 666 ${ABS_MOUNT_PATH}/dev/null c 1 3
sudo chroot ${ABS_MOUNT_PATH} apt update

CPC_SBOM_SCRIPT_PATH=$(which cpc-sbom)

sudo ${CPC_SBOM_SCRIPT_PATH} --ignore-copyright-parsing-errors --ignore-copyright-file-not-found-errors --rootdir ./ubuntu-cloud-image-mnt > "${CLOUD_IMAGE_SPDX}" 2> "${CLOUD_IMAGE_SPDX_GENERATION_LOG}" && echo "SBOM generation successfull" || echo "SBOM generation generated warnings or errors. See '${CLOUD_IMAGE_SPDX_GENERATION_LOG}' for details"

sudo rm -rf ${ABS_MOUNT_PATH} ${CLOUD_IMAGE}