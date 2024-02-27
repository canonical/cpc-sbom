#!/usr/bin/env python3
CPC_SBOM_VERSION = "0.1.18"

if __name__ == "__main__":
    from generate import generate_sbom

    generate_sbom()
