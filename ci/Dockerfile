# Pinned CI image for the YARA ruleset pipeline (lint / build / test).
#
# yara-python bundles the libyara source in its sdist, but there is no cp314
# manylinux wheel yet, so pip compiles it from source. That needs a C toolchain
# plus libssl-dev (for the pe/hash modules). The build deps are purged after the
# install to keep the image lean; libssl3 (runtime) stays via the base image.
# Base image is pinned by multi-arch index digest for reproducibility (NFR-6);
# resolve a new digest with `docker buildx imagetools inspect python:3.14-slim-bookworm`.
FROM python:3.14-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30

WORKDIR /app

# Dependency versions are pinned in requirements.txt so the layer is deterministic.
COPY requirements.txt .
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends build-essential libssl-dev; \
    pip install --no-cache-dir -r requirements.txt; \
    apt-get purge -y --auto-remove build-essential libssl-dev; \
    rm -rf /var/lib/apt/lists/*

# No ENTRYPOINT: CI jobs supply their own command (lint.py / build_ruleset.py / pytest).
