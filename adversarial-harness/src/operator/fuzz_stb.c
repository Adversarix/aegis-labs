// libFuzzer harness for the walking-skeleton operator loop: decode arbitrary bytes
// as an image through stb_image, under ASan. This is OUR harness; the target
// (stb_image) is a real third-party library ingested and built in the sandbox. A
// memory-safety defect in stb surfaces here as an ASan / libFuzzer finding with a
// reproducer, which the operator loop then takes into custody. Real discovery on
// real code, fully contained (the run is --network none).
#define STB_IMAGE_IMPLEMENTATION
#define STBI_NO_STDIO
#include "stb_image.h"
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int x, y, channels;
  unsigned char *img = stbi_load_from_memory(data, size, &x, &y, &channels, 4);
  if (img) stbi_image_free(img);
  return 0;
}
