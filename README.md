# cpc-sbom
CPC maintained tool for generating SBOM for cloud images

## Usage
```
$  cpc-sbom --help
usage: cpc-sbom [-h] [--rootdir ROOTDIR] [--ignore-copyright-parsing-errors] [--ignore-copyright-file-not-found-errors] [--include-installed-files]

Create Software Bill Of Materials (SBOM) in spdx format

options:
  -h, --help            show this help message and exit
  --rootdir ROOTDIR     Root directory of the Ubuntu cloud image filesystem which you wish to generate an SBOM for. This is useful if you are generating an SBOM for a mounted filesystem rather than the host. Default: /
  --ignore-copyright-parsing-errors
                        Ignore copyright parsing errors.
  --ignore-copyright-file-not-found-errors
                        Ignore copyright file not found errors.
  --include-installed-files
                        Include all installed files from all installed packages in SBOM.
```

## Demo

See [demo/demo.sh](demo/demo.sh) directory for a demo of how to use this tool.

See [demo/ubuntu-22.04-server-cloudimg-amd64.img.spdx](demo/ubuntu-22.04-server-cloudimg-amd64.img.spdx) for an example SPDX SBOM for a recent Ubuntu 22.04 cloud image generated with this tool.

See [demo/ubuntu-22.04-server-cloudimg-amd64.img_installed_files.spdx](demo/ubuntu-22.04-server-cloudimg-amd64.img_installed_files.spdx) for an example SPDX SBOM for a recent Ubuntu 22.04 cloud image generated with this tool including the listing of all files installed during package installs.

