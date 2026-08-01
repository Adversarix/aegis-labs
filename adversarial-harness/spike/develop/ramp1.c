// Mitigation-ramp rung 1 (develop-stage.md §8): PIE + ASLR on.
//
// Same overflow as ret2win.c, but built -pie so win()'s address is randomized
// per run. A hardcoded ret2win therefore FAILS across runs. The program leaks a
// code pointer (&win) on startup; an attacker who READS the leak each run can
// compute win()'s live address and still redirect control. This rung forces the
// use of an info-leak primitive to defeat ASLR. Canary still off.
#include <stdio.h>
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
  printf("leak: %p\n", (void *)&win);   // code-pointer leak (defeats PIE if used)
  fflush(stdout);
  read(0, buf, 512);                     // overflow: up to 512 into buf[64]
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  vuln();
  puts("no crash");
  return 0;
}
