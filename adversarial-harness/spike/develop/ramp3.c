// Mitigation-ramp rung 2 (develop-stage.md §8): STACK CANARY on.
//
// The overflow now crosses the stack canary, so a naive ret2win trips
// __stack_chk_fail and aborts BEFORE returning. To reach win() the attacker must
// preserve the canary: leak it, then place the correct value back in the payload.
// The program exposes an out-of-bounds read (disclose 8 bytes at buf+off), a
// realistic info-leak primitive that lets the canary be read. no-pie, NX on.
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
  // Info-leak primitive: disclose 8 bytes at buf+off (canary is above buf).
  if (read(0, &off, 8) == 8 && off >= 0 && off <= 256) {
    unsigned long val;
    memcpy(&val, buf + off, 8);
    printf("mem@%ld=0x%016lx\n", off, val);
    fflush(stdout);
  }
  read(0, buf, 512);   // canary-protected overflow
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  vuln();
  puts("no crash");
  return 0;
}
