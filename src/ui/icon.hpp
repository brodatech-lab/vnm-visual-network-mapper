#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

namespace vnm::ui {

/// Draws the VNM application icon (a magnifier over a small network) into an
/// RGBA buffer of `size` x `size` pixels. Used both at runtime (window icon)
/// and by the asset generator that produces vnm.png / vnm.ico.
inline void draw_vnm_icon(std::uint8_t* out, int size) {
    constexpr int ss = 4; // supersampling factor (antialiasing)
    const int hi = size * ss;
    const float S = static_cast<float>(hi);

    std::vector<float> buf(static_cast<std::size_t>(hi) * hi * 4, 0.0f);

    auto put = [&](int x, int y, float r, float g, float b) {
        if (x < 0 || y < 0 || x >= hi || y >= hi) {
            return;
        }
        float* p = &buf[(static_cast<std::size_t>(y) * hi + x) * 4];
        p[0] = r;
        p[1] = g;
        p[2] = b;
        p[3] = 1.0f;
    };

    const auto seg_dist = [](float px, float py, float ax, float ay, float bx, float by) {
        const float dx = bx - ax;
        const float dy = by - ay;
        const float len2 = dx * dx + dy * dy;
        float t = len2 > 0.0f ? ((px - ax) * dx + (py - ay) * dy) / len2 : 0.0f;
        t = std::min(std::max(t, 0.0f), 1.0f);
        const float qx = ax + t * dx;
        const float qy = ay + t * dy;
        return std::sqrt((px - qx) * (px - qx) + (py - qy) * (py - qy));
    };

    const float margin = 0.06f * S;
    const float corner = 0.22f * S;
    const float cx = 0.42f * S;
    const float cy = 0.40f * S;
    const float ring = 0.27f * S;
    const float ring_th = 0.058f * S;
    const float hx = cx + ring * 0.70f;
    const float hy = cy + ring * 0.70f;
    const float handle_th = 0.075f * S;

    const float n1x = 0.33f * S;
    const float n1y = 0.32f * S;
    const float n2x = 0.51f * S;
    const float n2y = 0.31f * S;
    const float n3x = 0.42f * S;
    const float n3y = 0.50f * S;
    const float node_r = 0.038f * S;

    for (int y = 0; y < hi; ++y) {
        for (int x = 0; x < hi; ++x) {
            const float px = static_cast<float>(x) + 0.5f;
            const float py = static_cast<float>(y) + 0.5f;

            // rounded-rect background
            bool inside = false;
            const float x0 = margin;
            const float y0 = margin;
            const float x1 = S - margin;
            const float y1 = S - margin;
            if (px >= x0 && px <= x1 && py >= y0 && py <= y1) {
                float dx = 0.0f;
                float dy = 0.0f;
                if (px < x0 + corner) {
                    dx = (x0 + corner) - px;
                } else if (px > x1 - corner) {
                    dx = px - (x1 - corner);
                }
                if (py < y0 + corner) {
                    dy = (y0 + corner) - py;
                } else if (py > y1 - corner) {
                    dy = py - (y1 - corner);
                }
                inside = dx * dx + dy * dy <= corner * corner;
            }
            if (!inside) {
                continue;
            }
            put(x, y, 0.094f, 0.102f, 0.122f); // #181a1f

            // glass ring
            const float d = std::sqrt((px - cx) * (px - cx) + (py - cy) * (py - cy));
            if (std::fabs(d - ring) <= ring_th * 0.5f) {
                put(x, y, 0.29f, 0.64f, 1.0f); // accent
            }
            // handle
            if (seg_dist(px, py, hx, hy, 0.80f * S, 0.80f * S) <= handle_th * 0.5f) {
                put(x, y, 0.29f, 0.64f, 1.0f);
            }
            // network lines inside the glass
            const float lw = 0.022f * S * 0.5f;
            if (seg_dist(px, py, n1x, n1y, n2x, n2y) <= lw ||
                seg_dist(px, py, n1x, n1y, n3x, n3y) <= lw ||
                seg_dist(px, py, n2x, n2y, n3x, n3y) <= lw) {
                put(x, y, 0.45f, 0.50f, 0.56f);
            }
            // nodes
            auto node = [&](float nx, float ny, float r, float g, float b) {
                if ((px - nx) * (px - nx) + (py - ny) * (py - ny) <= node_r * node_r) {
                    put(x, y, r, g, b);
                }
            };
            node(n1x, n1y, 0.18f, 0.80f, 0.44f); // safe green
            node(n2x, n2y, 0.95f, 0.77f, 0.06f); // warning yellow
            node(n3x, n3y, 0.91f, 0.30f, 0.24f); // critical red
        }
    }

    // box-downsample to the requested size
    for (int y = 0; y < size; ++y) {
        for (int x = 0; x < size; ++x) {
            float sum[4] = {0.0f, 0.0f, 0.0f, 0.0f};
            for (int sy = 0; sy < ss; ++sy) {
                for (int sx = 0; sx < ss; ++sx) {
                    const float* p =
                        &buf[((static_cast<std::size_t>(y * ss + sy) * hi) + (x * ss + sx)) * 4];
                    sum[0] += p[0];
                    sum[1] += p[1];
                    sum[2] += p[2];
                    sum[3] += p[3];
                }
            }
            const float n = static_cast<float>(ss * ss);
            const float a = sum[3] / n;
            std::uint8_t* o = &out[(static_cast<std::size_t>(y) * size + x) * 4];
            if (a <= 0.001f) {
                o[0] = o[1] = o[2] = o[3] = 0;
            } else {
                o[0] = static_cast<std::uint8_t>(std::min(255.0f, (sum[0] / n) / a * 255.0f));
                o[1] = static_cast<std::uint8_t>(std::min(255.0f, (sum[1] / n) / a * 255.0f));
                o[2] = static_cast<std::uint8_t>(std::min(255.0f, (sum[2] / n) / a * 255.0f));
                o[3] = static_cast<std::uint8_t>(a * 255.0f);
            }
        }
    }
}

} // namespace vnm::ui
