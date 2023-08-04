import debian.copyright

from cpc_sbom.generate import (
    _get_package_copyright,
    _get_package_licenses,
    _generate_document_namespace,
    _get_installed_snaps,
)
from unittest import TestCase
from tests.conftest import MOCK_COPYRIGHT, MOCK_SNAP_STATE_FILE, EXPECTED_SNAPS, MOCK_DOCUMENT_NAME

# Create object for accessing unittest assertions
assertions = TestCase("__init__")


def test_raise_copyright_parsing_error():
    """
    Verify that a parsing error is raised when a package's copyright text
    is not machine readable and --ignore-copyright-parsing-errors isn't specified
    """
    with assertions.assertRaises(ValueError or debian.copyright.NotMachineReadableError):
        _get_package_licenses("openssh-client", MOCK_COPYRIGHT, [], False)


def test_raise_copyright_file_not_found_error():
    """
    Verify that a file not found error is raised when a package's copyright file
    is not found and --ignore-copyright-file-not-found-errors isn't specified
    """
    with assertions.assertRaises(FileNotFoundError):
        _get_package_copyright(".", "some-package", "some-package", False)


def test_parse_license_manually():
    """
    Verify that the licenses from a package's copyright text that is not
    machine readable but has the licenses in it are grepped manually
    """
    licenses = _get_package_licenses("openssh-client", MOCK_COPYRIGHT, [], True)
    assert licenses


def test_generate_unique_document_namespace():
    """
    Verify that each document namespace generated is unique
    """
    document_namespace = _generate_document_namespace(MOCK_DOCUMENT_NAME)
    assert document_namespace != _generate_document_namespace(MOCK_DOCUMENT_NAME)


def test_get_installed_snaps():
    """
    Verify that a snap state file is parsed correctly to get all the
    required information
    """
    snaps = _get_installed_snaps("./tests", MOCK_SNAP_STATE_FILE, False)

    assert EXPECTED_SNAPS == snaps
