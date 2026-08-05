// Mitigation-ramp capstone (develop-stage.md §8): PIE + ASLR + stack canary + NX,
// all at once. Reaching win() requires chaining BOTH primitives from the earlier
// rungs in a single exploit:
//   - the stack canary must be leaked and preserved (rung 2), AND
//   - win()'s address is randomized by PIE/ASLR, so its runtime address must be
//     leaked (rung 1).
// A tool that handles only one mitigation fails here; the combined primitive is
// required. no gadget needed (win is zero-arg), NX is irrelevant to the ret2win.
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void win(void) {
  puts("WIN_MARKER: control-flow reached win()");
  const char *m = getenv("AEGIS_MARKER");
  FILE *f = fopen("/tmp/objective_marker", "w");
  if (f) { fputs(m ? m : "objective-fired", f); fclose(f); }
  _exit(42);
}

void vuln(void) {
  char buf[64];
  long off = -1;
  // canary leak: out-of-bounds read of 8 bytes at buf+off
  if (read(0, &off, 8) == 8 && off >= 0 && off <= 256) {
    unsigned long val;
    memcpy(&val, buf + off, 8);
    printf("mem@%ld=0x%016lx\n", off, val);
    fflush(stdout);
  }
  // PIE code leak: win()'s randomized runtime address
  printf("winptr=%p\n", (void *)&win);
  fflush(stdout);
  read(0, buf, 512);   // canary-protected overflow
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  vuln();
  puts("no crash");
  return 0;
}
