# Green-tier sandbox image for the Day-4 discovery loop. Built on the
# locally-available ubuntu:22.04. apt runs at BUILD time (network allowed then);
# the container is always RUN with --network none (see run-poc.sh / fuzz.sh).
FROM ubuntu:22.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      clang llvm \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY vuln.c poc_main.c /work/

# run_poc build: ASan only, deterministic, no libFuzzer needed.
# -O0 so the write into buf is not dead-store-eliminated (buf is never read),
# which at -O1 would optimize the overflow away and mask the bug.
RUN clang -g -O0 -fsanitize=address poc_main.c vuln.c -o /work/vuln_poc

# fuzz build: libFuzzer + ASan. Best-effort — if this clang lacks the fuzzer
# runtime the image still builds and only the fuzz tool is unavailable.
RUN clang -g -O1 -fsanitize=address,fuzzer vuln.c -o /work/vuln_fuzz \
    || echo "WARN: libFuzzer unavailable in this image; vuln_fuzz not built"

ENV ASAN_OPTIONS=abort_on_error=1:detect_leaks=0
