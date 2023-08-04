#!/bin/bash -eux
CLOUD_IMAGE="$1"
CLOUD_IMAGE_SPDX="tests/inject-ubuntu-jammy-oci-amd64-root.tar.gz.spdx"

CPC_SBOM_INJECT_SCRIPT_PATH=$(which cpc-sbom-inject)

${CPC_SBOM_INJECT_SCRIPT_PATH} "${CLOUD_IMAGE}" "${CLOUD_IMAGE_SPDX}"
