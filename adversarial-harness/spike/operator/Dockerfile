# Operator walking-skeleton target image: INGEST a real third-party target into the
# box and build it for hunting. stb_image is a public-domain / MIT single-header
# image decoder (permissive-deps-only). The pinned commit is a 2018-era stb_image
# (v2.19), before OSS-Fuzz hardening, so a hunt reliably surfaces a real defect.
#
# Build has network (fetch + apt); runs are --network none (green sandbox).
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang curl ca-certificates file \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Ingest the real target source, pinned to an exact commit (verifiable).
ARG STB_COMMIT=f54acd4e13430c5122cab4ca657705c84aa61b08
RUN curl -fsSL "https://raw.githubusercontent.com/nothings/stb/${STB_COMMIT}/stb_image.h" -o stb_image.h

COPY fuzz_stb.c /src/
RUN mkdir -p /work \
 && clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address fuzz_stb.c -o /work/fuzz_stb \
 && file /work/fuzz_stb

# Provenance for the operator loop / disclosure record.
RUN printf '{"target":"stb_image","version":"2.19","commit":"%s","license":"MIT / public domain","source":"github.com/nothings/stb"}\n' "${STB_COMMIT}" > /work/target.json

WORKDIR /work
