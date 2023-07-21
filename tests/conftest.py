# copyright text from the openssh-client package, that is not machine readable but has the licenses in it
MOCK_COPYRIGHT = open("tests/fixtures/openssh-client-copyright", "r").read()
MOCK_DOCUMENT_NAME = "ubuntu-22.04-server-cloudimg-example"

# example snap state.json file and contents
MOCK_SNAP_STATE_FILE = "tests/mock-state.json"

EXPECTED_SNAPS = [
    {
        "name": "core18",
        "version": "2785",
        "checksums": [],
        "comment": '"Channel: latest/stable"',
        "reference_locator": "pkg:generic/core18@2785?channel=latest/stable",
        "installed_files": [],
    },
    {
        "name": "core20",
        "version": "1974",
        "checksums": [],
        "comment": '"Channel: latest/stable"',
        "reference_locator": "pkg:generic/core20@1974?channel=latest/stable",
        "installed_files": [],
    },
    {
        "name": "snapd",
        "version": "19457",
        "checksums": [],
        "comment": '"Channel: latest/stable"',
        "reference_locator": "pkg:generic/snapd@19457?channel=latest/stable",
        "installed_files": [],
    },
]

MOCK_SBOM_FILE = "tests/mock-ubuntu-jammy-oci-amd64-root.tar.gz.spdx"
TEST_GENERATE_SBOM_FILE = "tests/ubuntu-jammy-oci-amd64-root.tar.gz.spdx"
TEST_INJECT_SBOM_FILE = "tests/inject-ubuntu-jammy-oci-amd64-root.tar.gz.spdx"
