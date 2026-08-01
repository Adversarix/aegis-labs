# Develop-stage green sandbox: exploit-dev toolchain (develop-stage.md §5).
# Built on ubuntu:22.04. apt/pip run at BUILD time (network allowed then); the
# container is always RUN with --network none. ASLR is irrelevant to the
# mitigations-off ret2win (no-pie => fixed addresses), so no host sysctl needed.
FROM ubuntu:22.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      gcc gdb python3 python3-pip file binutils \
 && rm -rf /var/lib/apt/lists/*

# pwntools drives the persistent process + gdb; ropper/ROPgadget for gadget_search.
RUN pip3 install --no-cache-dir pwntools==4.13.1 ropper==1.13.8

# C headers for compiling the target (--no-install-recommends skipped libc6-dev).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libc6-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY ret2win.c session_server.py /work/

# Build-first rung: mitigations OFF. NX left on (ret2win jumps to existing code).
RUN gcc -fno-stack-protector -no-pie -g -O0 ret2win.c -o /work/ret2win \
 && file /work/ret2win

ENV PYTHONUNBUFFERED=1 PWNLIB_NOTERM=1
