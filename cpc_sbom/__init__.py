#!/usr/bin/env python3
import json

import apt
import re

from datetime import datetime
from jinja2 import Environment, FileSystemLoader

cache = apt.Cache()


def generate_sbom():
    # query apt cache to list all the packages installed
    installed_packages = []
    for package in cache:
        if package.is_installed:
            package_installed_files = package.installed_files
            package_copyright_file = None
            package_copyright = ""
            package_licenses = []
            # find the copyright file in the installed files list
            for package_installed_file in package_installed_files:
                if package_installed_file.endswith("copyright"):
                    package_copyright_file = package_installed_file
                    break
            # if the copyright file is found, read the file and get the sha256
            if package_copyright_file:
                with open(
                    package_copyright_file, "r", encoding="utf-8", errors="ignore"
                ) as copyright_file:
                    package_copyright = copyright_file.read()

            # use regular expression to get the Licenses from the copyright file
            if package_copyright:
                package_licenses = re.findall(
                    r"License: (.*)", package_copyright, re.MULTILINE
                )
                package_licenses = list(set(package_licenses))

            package_installed_record = package.installed.record
            package_name = package.name
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
    jinja2_environment = Environment(loader=FileSystemLoader("cpc_sbom/templates/"))
    jinja2_spdx_template = jinja2_environment.get_template("spdx.jinja2")
    spdx_output = jinja2_spdx_template.render(
        installed_packages=installed_packages, creation_date=datetime.now()
    )
    spdx_output_json = json.loads(spdx_output)  # convert the spdx output to json to ensure valid json
    print(json.dumps(spdx_output_json, indent=4))


if __name__ == "__main__":
    generate_sbom()
