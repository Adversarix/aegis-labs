// Develop-stage build-first target (develop-stage.md §8): a classic ret2win.
//
// vuln() reads 512 bytes into a 64-byte stack buffer -> saved return address is
// overwritable. win() is never called on any legitimate path; reaching it is the
// OBJECTIVE and is machine-verifiable via a signed marker file + a stdout marker.
//
// Built mitigations-OFF first (-fno-stack-protector -no-pie) so the ladder is
// climbable without a full bypass chain. win() deliberately avoids system() to
// dodge the movaps stack-alignment pitfall — reaching win() is the whole test.
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void win(void) {
  puts("WIN_MARKER: control-flow reached win()");
  // Machine-verifiable objective: fire the marker file the harness checks.
  // The signed run marker is injected by the seam as $AEGIS_MARKER.
  const char *m = getenv("AEGIS_MARKER");
  FILE *f = fopen("/tmp/objective_marker", "w");
  if (f) { fputs(m ? m : "objective-fired", f); fclose(f); }
  _exit(42);
}

void vuln(void) {
  char buf[64];
  puts("send your input:");
  fflush(stdout);
  read(0, buf, 512);   // overflow: up to 512 bytes into buf[64]
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  vuln();
  puts("no crash");
  return 0;
}
