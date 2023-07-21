#!/bin/bash -eux
CLOUD_IMAGE_PATH="tests/fixtures/ubuntu-jammy-oci-amd64-root.tar.gz"
CLOUD_IMAGE_NAME="ubuntu-jammy-oci-amd64-root.tar.gz"
CLOUD_IMAGE_SPDX="tests/${CLOUD_IMAGE_NAME}.spdx"
DOCUMENT_NAME="ubuntu-jammy-oci-amd64"

MOUNTPOINT="./ubuntu-oci-image"
ABS_MOUNT_PATH=$(realpath ${MOUNTPOINT})
mkdir --parents ${ABS_MOUNT_PATH}

rm --force ${CLOUD_IMAGE_SPDX}


tar -xf ${CLOUD_IMAGE_PATH} -C ${ABS_MOUNT_PATH}
CPC_SBOM_SCRIPT_PATH=$(which cpc-sbom)


${CPC_SBOM_SCRIPT_PATH} --ignore-copyright-parsing-errors --ignore-copyright-file-not-found-errors --rootdir ${ABS_MOUNT_PATH} --rootdir-architecture amd64 --document-name ${DOCUMENT_NAME} > "${CLOUD_IMAGE_SPDX}"

rm -rf ${ABS_MOUNT_PATH}