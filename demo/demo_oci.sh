#!/bin/bash -eux
CLOUD_IMAGE_ARCHITECTURE="amd64"
CLOUD_IMAGE="ubuntu-jammy-oci-${CLOUD_IMAGE_ARCHITECTURE}-root.tar.gz"
CLOUD_IMAGE_SPDX="${CLOUD_IMAGE}.spdx"
CLOUD_IMAGE_SPDX_GENERATION_LOG="${CLOUD_IMAGE}.spdx.log"
DOCUMENT_NAME="ubuntu-jammy-oci-${CLOUD_IMAGE_ARCHITECTURE}"

CLOUD_IMAGE_SPDX_INCLUDING_INSTALLED_FILES="${CLOUD_IMAGE}_installed_files.spdx"
CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES="${CLOUD_IMAGE}_installed_files.spdx.log"

if [ ! -f ${CLOUD_IMAGE} ]; then
    wget https://partner-images.canonical.com/oci/jammy/current/${CLOUD_IMAGE} -O ${CLOUD_IMAGE}
fi

MOUNTPOINT="./ubuntu-oci-image"
ABS_MOUNT_PATH=$(realpath ${MOUNTPOINT})
mkdir --parents ${ABS_MOUNT_PATH}

rm --force ${CLOUD_IMAGE_SPDX_GENERATION_LOG} ${CLOUD_IMAGE_SPDX} ${CLOUD_IMAGE_SPDX_INCLUDING_INSTALLED_FILES} ${CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES}

# permit to keep the permission for the /tmp/ folder

sudo tar --same-owner -xf ${CLOUD_IMAGE} -C ${ABS_MOUNT_PATH}
CPC_SBOM_SCRIPT_PATH=$(which cpc-sbom)


sudo ${CPC_SBOM_SCRIPT_PATH} --ignore-copyright-parsing-errors --ignore-copyright-file-not-found-errors --rootdir ${ABS_MOUNT_PATH} --update-apt-cache --rootdir-architecture ${CLOUD_IMAGE_ARCHITECTURE} --document-name ${DOCUMENT_NAME} > "${CLOUD_IMAGE_SPDX}" 2> "${CLOUD_IMAGE_SPDX_GENERATION_LOG}" && echo "SBOM generation successfull" || echo "SBOM generation generated warnings or errors. See '${CLOUD_IMAGE_SPDX_GENERATION_LOG}' for details"
sudo ${CPC_SBOM_SCRIPT_PATH} --update-apt-cache --rootdir-architecture ${CLOUD_IMAGE_ARCHITECTURE} --ignore-copyright-parsing-errors --ignore-copyright-file-not-found-errors --include-installed-files --rootdir ${ABS_MOUNT_PATH} --document-name ${DOCUMENT_NAME} > "${CLOUD_IMAGE_SPDX_INCLUDING_INSTALLED_FILES}" 2> "${CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES}" && echo "SBOM including installed files generation successfull" || echo "SBOM including installed files generation generated warnings or errors. See '${CLOUD_IMAGE_SPDX_GENERATION_LOG_INCLUDING_INSTALLED_FILES}' for details"

sudo rm -rf ${ABS_MOUNT_PATH} ${CLOUD_IMAGE}
