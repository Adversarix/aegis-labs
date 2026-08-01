// Deliberately-vulnerable, benign, in-box target (week-one-spike.md Day 4).
// libFuzzer entrypoint: a fixed 16-byte stack buffer overflows when the input
// is longer than 16 bytes. ASan reports the stack-buffer-overflow.
#include <string.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {
  char buf[16];
  if (n) memcpy(buf, d, n);   // overflow when n > 16
  // Consume buf so the copy is not dead-store-eliminated. Without this, an
  // optimizing build (-O1+) proves buf is never read and removes the write,
  // masking the overflow. The read below is always in-bounds; the bug is the
  // out-of-bounds *write* in the memcpy above, which ASan catches when n > 16.
  volatile char sink = buf[n % sizeof(buf)];
  (void)sink;
  return 0;
}
