// Deterministic driver for run_poc: reads stdin and runs the SAME vulnerable
// function (vuln.c) once, under ASan, with no libFuzzer dependency. An input
// longer than 16 bytes triggers the stack-buffer-overflow ASan report.
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

int main(void) {
  static uint8_t b[65536];
  size_t n = fread(b, 1, sizeof(b), stdin);
  return LLVMFuzzerTestOneInput(b, n);
}
