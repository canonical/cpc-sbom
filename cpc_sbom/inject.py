#!/usr/bin/env python3
import argparse
import json
import logging


class SBOMFormatError(Exception):
    pass


logger = logging.getLogger(__name__)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inject a value into an existing SBOM")
    parser.add_argument(
        "artifact_name",
        help="Artifact name to inject. This should be the image filename. "
        "E.g. jammy-minimal-cloudimg-amd64-gke-1.26.img",
    )
    parser.add_argument(
        "sbom_file",
        help="Existing SBOM to inject values into. " "E.g. jammy-minimal-cloudimg-amd64-gke-1.26.img.sbom.spdx",
    )

    return parser


def inject_artifact_name() -> None:
    # parse arguments using argparse
    parser = _parser()
    args = parser.parse_args()
    artifact_name = args.artifact_name
    sbom_file = args.sbom_file

    with open(sbom_file, "r") as f:
        spdx_content = json.load(f)

    try:
        # find value to replace
        document_name = spdx_content["documentDescribes"][0].split("SPDXRef-")[1]
        spdx_output = json.dumps(spdx_content).replace(document_name, artifact_name)
        spdx_output_json = json.loads(spdx_output)  # convert the spdx output to json to ensure valid json
    except IndexError as e:
        raise SBOMFormatError("The documentDescribes field in the SBOM file is empty") from e

    with open(sbom_file, "w") as f:
        f.write(json.dumps(spdx_output_json, indent=4))


if __name__ == "__main__":
    inject_artifact_name()
