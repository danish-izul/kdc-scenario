#include "sha256.hpp"

#include <cstdio>

#include "trace.hpp"

namespace sha256 {

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static std::string w32(uint32_t v) {
    char b[9];
    snprintf(b, sizeof b, "%08x", v);
    return b;
}

Bytes hash(const Bytes& msg, bool show) {
    Bytes m = msg;
    const uint64_t bit_len = static_cast<uint64_t>(msg.size()) * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0x00);
    put_u64(m, bit_len);
    const size_t blocks = m.size() / 64;

    if (show && trace::on(0)) {
        trace::out("    SHA-256 padding: message || 0x80 || 0x00... || length(64-bit) = " +
                   std::to_string(bit_len) + " bits");
        trace::hexdump(4, "padded message, " + std::to_string(blocks) + " block(s) of 64 bytes", m);
    }

    uint32_t H[8];
    for (int i = 0; i < 8; ++i) H[i] = H0[i];

    for (size_t blk = 0; blk < blocks; ++blk) {
        const uint8_t* p = &m[64 * blk];
        uint32_t W[64];
        for (int t = 0; t < 16; ++t) W[t] = get_u32(p + 4 * t);
        for (int t = 16; t < 64; ++t) {
            uint32_t s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >> 3);
            uint32_t s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >> 10);
            W[t] = W[t - 16] + s0 + W[t - 7] + s1;
        }

        if (show && trace::on(2)) {
            trace::out("    block " + std::to_string(blk + 1) + ": message schedule W[0..63]");
            for (int t = 0; t < 64; t += 8) {
                std::string row;
                for (int k = 0; k < 8; ++k) row += w32(W[t + k]) + " ";
                char lbl[16];
                snprintf(lbl, sizeof lbl, "W[%2d..%2d]", t, t + 7);
                trace::out(std::string("      ") + lbl + " " + row);
            }
            trace::out("    block " + std::to_string(blk + 1) +
                       ": compression rounds    a        b        c        d        e        f        g        h");
        }

        uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
        for (int t = 0; t < 64; ++t) {
            uint32_t S1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch  = (e & f) ^ (~e & g);
            uint32_t T1  = h + S1 + ch + K[t] + W[t];
            uint32_t S0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t T2  = S0 + maj;
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
            if (show && trace::on(2)) {
                char lbl[16];
                snprintf(lbl, sizeof lbl, "t=%2d", t);
                trace::out(std::string("      ") + lbl + "                  " + w32(a) + " " + w32(b) + " " +
                           w32(c) + " " + w32(d) + " " + w32(e) + " " + w32(f) + " " + w32(g) + " " + w32(h));
            }
        }
        H[0] += a; H[1] += b; H[2] += c; H[3] += d;
        H[4] += e; H[5] += f; H[6] += g; H[7] += h;

        if (show && trace::on(1)) {
            std::string hs;
            for (int i = 0; i < 8; ++i) hs += w32(H[i]) + " ";
            trace::out("    after block " + std::to_string(blk + 1) + ": H = " + hs);
        }
    }

    Bytes digest;
    for (int i = 0; i < 8; ++i) put_u32(digest, H[i]);
    return digest;
}

} // namespace sha256
