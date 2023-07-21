import json
import subprocess
import pytest
import shutil
import os


from tests.conftest import MOCK_SBOM_FILE, TEST_GENERATE_SBOM_FILE, TEST_INJECT_SBOM_FILE, MOCK_DOCUMENT_NAME


@pytest.fixture
def run_oci_generate():
    """
    Run the oci test demo script, yield the resulting spdx content
    and clean up the test file
    """
    subprocess.run("./tests/oci_test_generate.sh")
    # remove everything that could change (document namespace, creation timestamp, cpc_sbom version)
    with open(TEST_GENERATE_SBOM_FILE, "r") as f:
        spdx_content = json.load(f)
    spdx_content["creationInfo"] = {}
    spdx_content["documentNamespace"] = ""
    spdx_output = json.dumps(spdx_content)
    spdx_output_json = json.loads(spdx_output)  # convert the spdx output to json to ensure valid json
    yield spdx_output_json
    # delete the generated sbom
    os.remove(TEST_GENERATE_SBOM_FILE)


def test_generate_oci_sbom(run_oci_generate):
    """
    Test sbom generation by running a test demo script for an oci image
    and comparing the result with the expected spdx content
    """
    with open(MOCK_SBOM_FILE, "r") as f:
        expected_spdx_content = json.load(f)

    assert expected_spdx_content == run_oci_generate


@pytest.fixture()
def copy_mock_spdx():
    """
    Create a copy of the mock spdx file to test the inject command on it
    and clean up the test file
    """
    shutil.copy(MOCK_SBOM_FILE, TEST_INJECT_SBOM_FILE)
    yield
    # delete the test file
    os.remove(TEST_INJECT_SBOM_FILE)


@pytest.mark.parametrize("artifact_name", ["ubuntu-jammy-oci-amd64-root.tar.gz", "not-a-real-image-name.tar.gz"])
def test_inject_oci_sbom(artifact_name, copy_mock_spdx):
    """
    Test the inject command by running an inject demo script for an oci image
    and comparing the results with the expected spdx content
    """
    subprocess.run(["./tests/oci_test_inject.sh", artifact_name])

    with open(TEST_INJECT_SBOM_FILE, "r") as f:
        spdx_content = json.load(f)

    spdx_content_str = json.dumps(spdx_content)
    assert "SPDXRef-{}".format(MOCK_DOCUMENT_NAME) != spdx_content["documentDescribes"][0]
    assert artifact_name in spdx_content["documentDescribes"][0]
    assert artifact_name == spdx_content["packages"][0]["name"]
    assert "SPDXRef-{}".format(MOCK_DOCUMENT_NAME) not in spdx_content_str
