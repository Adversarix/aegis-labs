// Mitigation-ramp rung 3 (develop-stage.md §8): NX on, no win() to jump to.
//
// There is no zero-argument win(): the objective is unlock(key), which fires the
// marker ONLY for a magic argument. A plain ret2win cannot pass an argument, so
// reaching the objective requires a ROP chain that (a) loads the magic value into
// the argument register (x0 on aarch64) and (b) calls unlock. NX is irrelevant to
// code reuse, which is the point: NX defeats shellcode, not ROP. no-pie, no canary.
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// Deliberate ROP gadget. aarch64 gcc binaries rarely contain an x0-loading
// gadget, so a controlled-argument chain is otherwise not constructible from this
// small binary. This is the standard aarch64 chaining gadget: load the argument
// register x0 AND the next return address x30 from the stack, then return. Its
// presence is what makes the rung a solvable ROP exercise (a deliberately-ROP-able
// target), not a statement about real-world gadget availability.
__asm__(
  ".text\n"
  ".global rop_gadget\n"
  "rop_gadget:\n"
  "    ldp x0, x30, [sp], #16\n"
  "    ret\n"
);

void unlock(long key) {
  if (key == 0xc0ffee) {
    puts("UNLOCK_MARKER: correct key, objective reached");
    const char *m = getenv("AEGIS_MARKER");
    FILE *f = fopen("/tmp/objective_marker", "w");
    if (f) { fputs(m ? m : "objective-fired", f); fclose(f); }
    _exit(42);
  }
  puts("wrong key");
}

void vuln(void) {
  char buf[64];
  read(0, buf, 512);   // overflow
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  vuln();
  puts("no crash");
  return 0;
}
