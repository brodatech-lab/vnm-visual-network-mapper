// Wrappers around the bundled stb single-header libraries. Compiled with
// warnings disabled (see CMake) because third-party headers are not -Werror
// clean.
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#include "stb_easy_font.h"

namespace vnm::stbwrap {

int png_write(const char* path, int width, int height, int components,
              const unsigned char* data, int stride) {
    return stbi_write_png(path, width, height, components, data, stride);
}

// Returns the number of bytes written into `buffer` (an array of 16-byte
// vertices: 3 floats x/y/z + 4 color bytes). Zero on failure.
int font_print(float x, float y, const char* text, const unsigned char color[4],
               void* buffer, int buffer_size) {
    unsigned char rgba[4] = {color[0], color[1], color[2], color[3]};
    return stb_easy_font_print(x, y, const_cast<char*>(text), rgba, buffer,
                               buffer_size);
}

int font_width(const char* text) {
    return stb_easy_font_width(const_cast<char*>(text));
}

int font_height(const char* text) {
    return stb_easy_font_height(const_cast<char*>(text));
}

} // namespace vnm::stbwrap
