#!/usr/bin/env python3
import json

import argparse
import apt
import logging
import os

from datetime import datetime
from debian.copyright import Copyright, NotMachineReadableError
from jinja2 import Environment, FileSystemLoader


logger = logging.getLogger(__name__)


def _parser():
    parser = argparse.ArgumentParser(description='Create Software Bill Of Materials (SBOM) in spdx format')
    parser.add_argument('--rootdir', help='Root directory of the Ubuntu cloud image filesystem which '
                                          'you wish to generate an SBOM for. This is useful if you are generating '
                                          'an SBOM for a mounted filesystem rather than the host. '
                                          'Default: %(default)s', default='/')
    parser.add_argument('--ignore-copyright-parsing-errors', help='Ignore copyright parsing errors. ',
                        action='store_true')
    parser.add_argument('--ignore-copyright-file-not-found-errors', help='Ignore copyright file not found errors. ',
                        action='store_true')
    return parser


def generate_sbom():
    # parse arguments using argparse
    parser = _parser()
    args = parser.parse_args()
    # root dir of the Ubuntu cloud image filesystem to generate an SBOM for (default: /).
    # Ensure that the rootdir has a trailing slash
    rootdir = args.rootdir if args.rootdir.endswith('/') else "{}/".format(args.rootdir)

    cache = apt.Cache(rootdir=rootdir)
    # query apt cache to list all the packages installed
    installed_packages = []
    for package in cache:
        if package.is_installed:
            package_name = package.name
            package_shortname = package.shortname
            package_installed_files = package.installed_files
            package_copyright = ""
            package_licenses = []
            # find the copyright file in filesystem
            package_copyright_file = "{}usr/share/doc/{}/copyright".format(rootdir, package_shortname)

            # if the copyright file is found and the file exists, read the file and get the license information
            # Note that not all copyright files are machine readable. If the copyright file is not machine readable,
            # then we will skip the file and move on to the next package if --ignore-copyright-parsing-errors is set.
            # If --ignore-copyright-parsing-errors is not set, then we will raise an exception and exit.
            # If the copyright file is not found, then we will skip the file and move on to the next package if
            # --ignore-copyright-file-not-found-errors is set. If --ignore-copyright-file-not-found-errors is not set,
            # then we will raise an exception and exit.
            try:
                with open(package_copyright_file, 'rt', encoding='utf-8', errors="ignore") as copyright_file:
                    package_copyright = copyright_file.read()
                    package_copyright_object = Copyright(copyright_file, strict=False)
                    all_copyright_paragraphs = package_copyright_object.all_paragraphs()
                    for copyright_paragraph in all_copyright_paragraphs:
                        if copyright_paragraph.license and copyright_paragraph.license.synopsis \
                                and copyright_paragraph.license.synopsis.strip():
                            package_licenses.append(copyright_paragraph.license.synopsis.strip())
            except ValueError as copyright_value_error:
                logger.warning("Unable to parse copyright file for package {} - {}: {}".format(
                    package_name,
                    package_copyright_file,
                    copyright_value_error))
                if not args.ignore_copyright_parsing_errors:
                    raise copyright_value_error
            except NotMachineReadableError as copyright_not_machine_readable_error:
                logger.warning("Copyright file for package {} is not machine readable - {}: {}".format(
                    package_name,
                    package_copyright_file,
                    copyright_not_machine_readable_error))
                if not args.ignore_copyright_parsing_errors:
                    raise copyright_not_machine_readable_error
            except FileNotFoundError as copyright_file_not_found_error:
                logger.warning("Copyright file not found for package {} - {}: {}".format(
                    package_name,
                    package_copyright_file,
                    copyright_file_not_found_error))
                if not args.ignore_copyright_file_not_found_errors:
                    # raise an exception if the copyright file is not found
                    raise copyright_file_not_found_error

            # ensure that package_licenses is a unique list
            package_licenses = list(set(package_licenses))

            package_installed_record = package.installed.record
            package_version = package.installed.version
            package_architecture = package.installed.architecture
            package_sha256 = package_installed_record.get("SHA256", "")
            package_sha512 = package_installed_record.get("SHA512", "")
            package_md5sum = package_installed_record.get("MD5sum", "")
            package_maintainer = package_installed_record.get("Maintainer")
            package_homepage = package.installed.homepage
            package_source_package_name = package.installed.source_name
            package_source_package_version = package.installed.source_version
            package_url = "http://{}/{}".format(
                package.installed.origins[0].site, package.installed.filename
            )
            package_reference_locator = (
                "pkg:deb/debian/{}@{}?arch={}&repository_url={}".format(
                    package_name, package_version, package_architecture, package_url
                )
            )
            checksums = []
            if package_sha256:
                checksums.append({"algorithm": "SHA256", "checksum": package_sha256})
            if package_sha512:
                checksums.append({"algorithm": "SHA512", "checksum": package_sha512})
            if package_md5sum:
                checksums.append({"algorithm": "MD5", "checksum": package_md5sum})
            installed_packages.append(
                {
                    "name": package_name,
                    "version": package_version,
                    "checksums": checksums,
                    "source_package_name": package_source_package_name,
                    "source_package_version": package_source_package_version,
                    "installed_files": package_installed_files,
                    "homepage": package_homepage,
                    "maintainer": package_maintainer,
                    "licenses": package_licenses,
                    "copyright": json.dumps(
                        package_copyright
                    ),  # ensure that the copyright is correctly escaped
                    "reference_locator": package_reference_locator,
                    "deb_url": package_url,
                }
            )
    # use jina2 template to generate the sbom using the spdx template
    abs_templates_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "templates")
    jinja2_environment = Environment(loader=FileSystemLoader(abs_templates_path))

    jinja2_spdx_template = jinja2_environment.get_template("spdx.jinja2")
    spdx_output = jinja2_spdx_template.render(
        installed_packages=installed_packages, creation_date=datetime.now()
    )
    spdx_output_json = json.loads(
        spdx_output
    )  # convert the spdx output to json to ensure valid json
    print(json.dumps(spdx_output_json, indent=4))


if __name__ == "__main__":
    generate_sbom()
