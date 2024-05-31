#!/usr/bin/env python3
import argparse
import json
import logging
import os
from datetime import datetime
from hashlib import sha256
from re import MULTILINE, findall
from typing import Any, List, Optional, Union
from uuid import uuid4

import apt
import apt_pkg
from debian.copyright import Copyright, NotMachineReadableError
from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

CPC_SBOM_VERSION = "0.1.21"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create Software Bill Of Materials (SBOM) in spdx format")
    parser.add_argument(
        "--rootdir",
        help="Root directory of the Ubuntu cloud image filesystem which "
        "you wish to generate an SBOM for. This is useful if you are generating "
        "an SBOM for a mounted filesystem rather than the host. "
        "Default: %(default)s",
        default="/",
    )
    parser.add_argument(
        "--rootdir-architecture",
        help="The architecture of the filesystem which you wish to generate an SBOM for. "
        "This is only required for when you use `--update-apt-cache` flag. This ensures "
        "that the apt cache inside the filesystem is updated with the correct"
        "architecture. The default for this flag is 'amd64'.",
        default="amd64",
    )
    parser.add_argument(
        "--ignore-copyright-parsing-errors", help="Ignore copyright parsing errors. ", action="store_true"
    )
    parser.add_argument(
        "--ignore-copyright-file-not-found-errors", help="Ignore copyright file not found errors. ", action="store_true"
    )
    parser.add_argument(
        "--update-apt-cache",
        help="Update the apt cache before generating the SBOM. "
        "Required for images/filesystems that have had the apt cache purged."
        "When this flag is used, you should run this tool as root user."
        "If the architecture of the filesystem you are generating an SBOM for is "
        "not 'amd64' then use the `--rootdir-architecture` flag to ensure your apt "
        "cache is updated with the correct architecture.",
        action="store_true",
    )
    parser.add_argument(
        "--include-installed-files",
        help="Include all installed files from all installed packages in SBOM. ",
        action="store_true",
    )
    parser.add_argument(
        "--document-name",
        help="Name for the SPDX document. This is typically the package name followed by the version. "
        "E.g. jammy-minimal-cloudimg-amd64-gke-1.26",
        required=True,
    )
    return parser


def _get_build_info(rootdir: str) -> str:
    """
    If this is an ubuntu cloud image, attempt to get the cloud image build info.
    """
    build_info = ""
    build_info_file = os.path.join(rootdir, "etc/cloud/build.info")
    if os.path.exists(build_info_file):
        with open(build_info_file, "rt", encoding="utf-8", errors="ignore") as f:
            build_info = f.read()
            # remove all new lines from the build info
            build_info = build_info.replace("\n", ", ")

    return build_info


def _generate_document_namespace(document_name: str) -> str:
    """
    Generates a unique URI to use as document namespace.
    (SPDX specification, clause 6.5)
    """
    # document namespace format: https://[CreatorWebsite]/[pathToSpdx]/[DocumentName]-[UUID]
    # This URI does not have to be accessible. It is only intended to provide a unique ID.
    document_uuid = uuid4()
    return "https://ubuntu.com/sbom/{}-{}".format(document_name, document_uuid)


def _calculate_file_sha256sum(file_path: Union[str, bytes]) -> str:
    """
    Calculates the sha256 checksum of a file.
    """
    with open(file_path, "rb") as f:
        return sha256(f.read()).hexdigest()


def _generate_file_identifier(file_path: Union[str, bytes]) -> str:
    """
    Generates a unique string to identify a file.
    (SPDX specification, clause 8.2)
    """
    return sha256(file_path.encode("utf-8")).hexdigest()  # type: ignore


def _update_apt_cache(rootdir_architecture: str, rootdir: str) -> apt.Cache:
    """
    Updates the apt cache.
    """
    # Change to using the root user when updating apt cache to avoid any apt_pkg.Error related to
    # > Download is performed unsandboxed as root as file'
    # > ... couldn't be accessed by user '_apt'. - pkgAcquire::Run (13: Permission denied),
    # We assume we are running this tool as root user when using the --update-apt-cache flag so
    # we can safely set the APT::Sandbox::User to root
    apt_pkg.config.set("APT::Sandbox::User", "root")
    if rootdir_architecture:
        apt_pkg.config.set("APT::Architecture", rootdir_architecture)
        apt_pkg.config.set("APT::Architectures", rootdir_architecture)
    apt_pkg.init_system()
    cache = apt.Cache(rootdir=rootdir)
    cache.update()
    cache.open()
    return cache


def _get_package_installed_files(rootdir: str, package_name: str, package_fullname: str) -> List[Any]:
    """
    Gets the information for all the files that were installed with a package.
    (SPDX specification, clause 8)
    """
    # We can't use `package.installed_files` from python-apt
    # https://salsa.debian.org/apt-team/python-apt/-/blob/main/apt/package.py#L1290
    # as this tries to read the metadata about the package's installed files from the
    # /var/lib/dpkg/info/<package>.list file, on the host system but for generating an SBOM on
    # a mounted filesystem, we need to read the metadata from the filesystem itself.
    # Instead of using `package.installed_files` to get the list of
    # installed files for a package we can use the same logic `package.installed_files`
    # as but ensure we read the metadata from the filesystem
    package_installed_files = []
    installed_files = []

    for name in package_name, package_fullname:
        path = os.path.join(rootdir, "var/lib/dpkg/info/{}.list".format(name))
        try:
            with open(path, "rb") as file_list:
                installed_files = file_list.read().decode("utf-8").split("\n")
        except EnvironmentError:
            continue

    for package_file_path in installed_files:
        # If we are using a rootdir other than / then we need to strip the initial os seperator
        # ('/' on linux) from the package file path. This is because if any of the arguments after rootdir
        # in os.path.join are absolute paths, then the initial path is discarded.
        package_file_absolute_file_path = os.path.join(rootdir, package_file_path.lstrip(os.sep))
        # only proceed if the file exists in the filesystem
        if os.path.isfile(package_file_absolute_file_path):
            package_installed_file_checksum = _calculate_file_sha256sum(package_file_absolute_file_path)
            package_file_dict = {
                # ensure the filename is valid and escaped json too
                "fileName": json.dumps(package_file_path),
                # Create a unique identifier for the file. We can't use the sha256 hash as the file may
                # be a symlink which would result in the same identifier for two different file paths on
                # disk. Instead, we use the file path and the sha256 hash of the file path.
                "identifier": _generate_file_identifier(package_file_path),
                "sha256": package_installed_file_checksum,
                "license": None,  # this will be populated later when parsing the copyright file
            }
            package_installed_files.append(package_file_dict)

    return package_installed_files


def _get_package_copyright(
    rootdir: str, package_name: str, package_shortname: str, ignore_copyright_file_not_found_errors: bool
) -> str:
    """
    Gets the copyright text for a package.
    (SPDX specification, clause 7.17)
    """
    package_copyright = ""

    # find the copyright file in filesystem
    package_copyright_file = os.path.join(rootdir, "usr/share/doc/{}/copyright".format(package_shortname))

    try:
        with open(package_copyright_file, "rt", encoding="utf-8", errors="ignore") as copyright_file:
            package_copyright = copyright_file.read()
    except FileNotFoundError as copyright_file_not_found_error:
        logger.warning(
            "Copyright file not found for package {} - {}: {}".format(
                package_name, package_copyright_file, copyright_file_not_found_error
            )
        )
        if not ignore_copyright_file_not_found_errors:
            # raise an exception if the copyright file is not found
            raise copyright_file_not_found_error

    return package_copyright


def _get_package_licenses(
    package_name: str, package_copyright: str, package_installed_files: List[Any], ignore_copyright_parsing_errors: bool
) -> List[Any]:
    """
    Gets the declared licenses for a package and its files.
    (SPDX specification, clauses 7.15 & 8.5)
    """
    package_licenses = []

    # if the copyright file is found and the file exists, read the file and get the license information
    # Note that not all copyright files are machine readable. If the copyright file is not machine readable
    # and if --ignore-copyright-parsing-errors is set then no exception is raised
    # If --ignore-copyright-parsing-errors is not set, then we will raise an exception and exit.
    # If the copyright file is not found, then we will skip the file and move on to the next package if
    # --ignore-copyright-file-not-found-errors is set. If --ignore-copyright-file-not-found-errors is not set,
    # then we will raise an exception and exit.
    # if the copyright file is not machine readble then we will attempt to parse manually by
    # grepping for "License:".
    try:
        package_copyright_object = Copyright(package_copyright.splitlines())
        all_copyright_paragraphs = package_copyright_object.all_paragraphs()
        for copyright_paragraph in all_copyright_paragraphs:
            if (
                copyright_paragraph.license
                and copyright_paragraph.license.synopsis  # type: ignore
                and copyright_paragraph.license.synopsis.strip()  # type: ignore
            ):
                package_licenses.append(copyright_paragraph.license.synopsis.strip())  # type: ignore
                # The license information can be retrieved for each package installed file from the
                # copyright file if it is machine readable and if the file is listed in a file
                # paragraph of the copyright file.
                for package_installed_file in package_installed_files:
                    file_specific_files_paragraph = package_copyright_object.find_files_paragraph(
                        package_installed_file["fileName"]
                    )
                    if file_specific_files_paragraph:
                        file_specific_license = file_specific_files_paragraph.license.synopsis.strip()  # type: ignore
                        package_installed_file["license"] = file_specific_license

    except (ValueError, NotMachineReadableError) as copyright_parsing_error:
        logger.warning(
            "Unable to parse copyright file for package {}: {}".format(package_name, copyright_parsing_error)
        )
        if not ignore_copyright_parsing_errors:
            raise copyright_parsing_error
        # If the copyright file is not in machine readable format then we need to grep for the license information
        # in the copyright file. This is not ideal but it is the best we can do.
        if package_copyright:
            manually_parsed_package_licenses = findall(r"^License: (.*)$\n", package_copyright, MULTILINE)
            manually_parsed_package_licenses_unique = list(set(manually_parsed_package_licenses))
            # strip any whitespace from the licenses
            package_licenses.extend(
                [
                    package_license.strip()
                    for package_license in manually_parsed_package_licenses_unique
                    if package_license.strip() != ""
                ]
            )

    # ensure that package_licenses is a unique list
    package_licenses = list(set(package_licenses))
    return package_licenses


def _get_package_url(package_installed: Optional[apt.package.Version]) -> str:
    """
    Gets the package origin URL. This is used as the download location and is also
    part of the reference locator.
    (SPDX specification clause 7.7)
    """
    package_origin_url = package_installed.origins[0].site  # type: ignore
    # If this SBOM is created during an image build on launchpad.net infrastructure, then the origin url
    # will be an internal launchpad ftpmaster.internal url . We need to convert this to a publicly
    # accessible url. The public url is the same as the internal url but with the ftpmaster.internal
    # part replaced with archive.ubuntu.com/ubuntu
    if "ftpmaster.internal" in package_origin_url:
        package_origin_url = package_origin_url.replace("ftpmaster.internal", "archive.ubuntu.com/ubuntu")
    return "http://{}/{}".format(package_origin_url, package_installed.filename)  # type: ignore


def _get_package_checksums(package_installed_record: apt.package.Record) -> List[Any]:
    """
    Gets the checksums for the package.
    (SPDX specification, clause 7.10)
    """
    package_sha256 = package_installed_record.get("SHA256", "")
    package_sha512 = package_installed_record.get("SHA512", "")
    package_md5sum = package_installed_record.get("MD5sum", "")

    checksums = []
    if package_sha256:
        checksums.append({"algorithm": "SHA256", "checksum": package_sha256})
    if package_sha512:
        checksums.append({"algorithm": "SHA512", "checksum": package_sha512})
    if package_md5sum:
        checksums.append({"algorithm": "MD5", "checksum": package_md5sum})

    return checksums


def _get_installed_packages(
    rootdir: str,
    cache: apt.Cache,
    include_installed_files: bool,
    ignore_copyright_parsing_errors: bool,
    ignore_copyright_file_not_found_errors: bool,
) -> List[Any]:
    """
    Gets the required information from all the installed packages in the filesystem.
    """
    installed_packages = []
    for package in cache:
        if package.is_installed:
            package_name = package.name
            package_shortname = package.shortname
            package_fullname = package.fullname
            package_installed_files = []

            # If specified, include all installed files from all installed packages in SBOM
            if include_installed_files:
                package_installed_files = _get_package_installed_files(rootdir, package_name, package_fullname)

            # find the copyright file in filesystem
            package_copyright = _get_package_copyright(
                rootdir, package_name, package_shortname, ignore_copyright_file_not_found_errors
            )
            package_licenses = _get_package_licenses(
                package_name, package_copyright, package_installed_files, ignore_copyright_parsing_errors
            )

            package_installed_record = package.installed.record  # type: ignore
            package_version = package.installed.version  # type: ignore
            package_architecture = package.installed.architecture  # type: ignore
            package_maintainer = package_installed_record.get("Maintainer")
            package_homepage = package.installed.homepage  # type: ignore
            package_source_package_name = package.installed.source_name  # type: ignore
            package_source_package_version = package.installed.source_version  # type: ignore
            package_url = _get_package_url(package.installed)
            package_reference_locator = "pkg:deb/debian/{}@{}?arch={}&repository_url={}".format(
                package_name, package_version, package_architecture, package_url
            )
            checksums = _get_package_checksums(package_installed_record)

            installed_packages.append(
                {
                    "name": package_name,
                    "short_name": package_shortname,
                    "full_name": package_fullname,
                    "version": package_version,
                    "checksums": checksums,
                    "source_package_name": package_source_package_name,
                    "source_package_version": package_source_package_version,
                    "installed_files": package_installed_files,
                    "homepage": package_homepage,
                    "maintainer": package_maintainer,
                    # sort the licenses to ensure that the order is consistent
                    "licenses": sorted(package_licenses),
                    "copyright": json.dumps(package_copyright),  # ensure that the copyright is correctly escaped
                    "reference_locator": package_reference_locator,
                    "deb_url": package_url,
                }
            )

    return installed_packages


def _get_snap_installed_files(rootdir: str, snap_name: str, snap_file_path: str) -> List[Any]:
    """
    Gets the information for all the files that were installed with a snap.
    (SPDX specification, clause 8)
    """
    snap_installed_files = []
    installed_files = [snap_file_path]
    snap_directory = os.path.join(rootdir, "snap/", snap_name)
    snap_files = os.walk(snap_directory)
    for path, _, files in snap_files:
        for file in files:
            installed_files.append(os.path.join(path, file))

    for file_path in installed_files:
        if os.path.isfile(file_path):
            snap_sha256sum = _calculate_file_sha256sum(file_path)
            # don't include the rootdir/mountpoint
            relative_file_path = file_path.split(rootdir)[1]
            snap_file_dict = {
                "fileName": json.dumps(relative_file_path),
                "identifier": _generate_file_identifier(file_path),
                "sha256": snap_sha256sum,
                "license": None,
            }
            snap_installed_files.append(snap_file_dict)

    return snap_installed_files


def _get_installed_snaps(rootdir: str, snap_state_file: str, include_installed_files: bool) -> List[Any]:
    """
    Gets the required information from all the installed and preseeded
    snaps in the filesystem.
    """
    installed_snaps = []
    if os.path.exists(snap_state_file):
        with open(snap_state_file, "r") as f:
            state = json.load(f)["data"]["snaps"]
            snap_names = list(state.keys())
            snap_names.sort()

        for snap_name in snap_names:
            snap_info = state[snap_name]

            snap_channel = snap_info.get("channel", "")
            snap_revision = snap_info["current"]
            snap_checksums = []
            snap_filename = "{}_{}.snap".format(snap_name, snap_revision)
            snap_file_path = os.path.join(rootdir, "var/lib/snapd/snaps/", snap_filename)
            if os.path.isfile(snap_file_path):
                snap_sha256sum = _calculate_file_sha256sum(snap_file_path)
                snap_checksums.append({"algorithm": "SHA256", "checksum": snap_sha256sum})
            # snaps aren't included in the purl-spec yet
            # ideally this should be something along the lines of pkg:snap/name@revision?channel
            # using a generic reference until changes get merged in to the purl-spec
            snap_reference_locator = "pkg:generic/{}@{}?channel={}".format(snap_name, snap_revision, snap_channel)

            snap_installed_files = []
            # If specified, include all installed files from all installed packages in SBOM
            if include_installed_files:
                snap_installed_files = _get_snap_installed_files(rootdir, snap_name, snap_file_path)

            installed_snaps.append(
                {
                    "name": snap_name,
                    "version": snap_revision,
                    "checksums": snap_checksums,
                    # channel usually has a slash
                    "comment": json.dumps("Channel: {}".format(snap_channel)),
                    "reference_locator": snap_reference_locator,
                    "installed_files": snap_installed_files,
                }
            )

    return installed_snaps


def generate_sbom() -> None:
    # parse arguments using argparse
    parser = _parser()
    args = parser.parse_args()
    # root dir of the Ubuntu cloud image filesystem to generate an SBOM for (default: /).
    # Ensure that the rootdir has a trailing slash
    rootdir = args.rootdir if args.rootdir.endswith("/") else "{}/".format(args.rootdir)

    if args.update_apt_cache:
        cache = _update_apt_cache(args.rootdir_architecture, rootdir)
    else:
        cache = apt.Cache(rootdir=rootdir)

    build_info = _get_build_info(rootdir)

    document_name = args.document_name
    document_namespace = _generate_document_namespace(document_name)

    # query apt cache to list all the packages installed
    packages = _get_installed_packages(
        rootdir,
        cache,
        args.include_installed_files,
        args.ignore_copyright_parsing_errors,
        args.ignore_copyright_file_not_found_errors,
    )

    # include preseeded and installed snaps
    snap_state_file = os.path.join(rootdir, "var/lib/snapd/state.json")
    snaps = _get_installed_snaps(rootdir, snap_state_file, args.include_installed_files)

    installed_packages = [*packages, *snaps]

    # use jinja2 template to generate the sbom using the spdx template
    abs_templates_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "templates")
    jinja2_environment = Environment(loader=FileSystemLoader(abs_templates_path))

    jinja2_spdx_template = jinja2_environment.get_template("spdx.jinja2")
    # Create date time in YYYY-MM-DDThh:mm:ssZ format to comply to SPDX spec
    # https://spdx.github.io/spdx-spec/v2.3/document-creation-information/#69-created-field
    created_date_time = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # get the version of the package that is being used to generate the sbom
    cpc_sbom_version = CPC_SBOM_VERSION

    spdx_output = jinja2_spdx_template.render(
        installed_packages=installed_packages,
        creation_date=created_date_time,
        build_info=build_info,
        cpc_sbom_version=cpc_sbom_version,
        document_namespace=document_namespace,
        document_name=document_name,
    )
    spdx_output_json = json.loads(spdx_output)  # convert the spdx output to json to ensure valid json
    print(json.dumps(spdx_output_json, indent=4))


if __name__ == "__main__":
    generate_sbom()
