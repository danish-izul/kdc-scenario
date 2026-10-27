#include "aes256.hpp"

#include <cstdio>
#include <cstring>
#include <string>

#include "trace.hpp"

namespace aes
{
static inline uint8_t xtime(uint8_t a) {
    return static_cast<uint8_t>((a << 1) ^ ((a & 0x80) ? 0x1b : 0x00));
}

uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b)
    {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

namespace {

inline uint8_t rotl8(uint8_t x, int s) { return static_cast<uint8_t>((x << s) | (x >> (8 - s))); }

struct Tables
{
    uint8_t s[256];
    uint8_t inv[256];
    Tables() {
        for (int x = 0; x < 256; ++x) {
            uint8_t xi = 0;
            for (int y = 1; x && y < 256; ++y)
                if (gf_mul(static_cast<uint8_t>(x), static_cast<uint8_t>(y)) == 1){
                    xi = static_cast<uint8_t>(y);
                    break;
                }
            uint8_t v = static_cast<uint8_t>(xi ^ rotl8(xi, 1) ^ rotl8(xi, 2) ^ rotl8(xi, 3) ^ rotl8(xi, 4) ^ 0x63);
            s[x] = v;
            inv[v] = static_cast<uint8_t>(x);
        }
    }
};

const Tables& T() {
    static const Tables t;
    return t;
}

// =====================
// round transformations
// =====================

void add_round_key(uint8_t s[16], const uint8_t* rk) {
    for (int i = 0; i < 16; ++i) s[i] ^= rk[i];
}

void sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; ++i) s[i] = T().s[s[i]];
}

void inv_sub_bytes(uint8_t s[16]) {
    for (int i = 0; i < 16; ++i) s[i] = T().inv[s[i]];
}

void shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r) t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
    std::memcpy(s, t, 16);
}

void inv_shift_rows(uint8_t s[16]) {
    uint8_t t[16];
    for (int c = 0; c < 4; ++c)
        for (int r = 0; r < 4; ++r) t[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
    std::memcpy(s, t, 16);
}

void mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* k = s + 4 * c;
        uint8_t a0 = k[0], a1 = k[1], a2 = k[2], a3 = k[3];
        k[0] = static_cast<uint8_t>(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
        k[1] = static_cast<uint8_t>(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
        k[2] = static_cast<uint8_t>(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
        k[3] = static_cast<uint8_t>(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
    }
}

void inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
            uint8_t* k = s + 4 * c;
            uint8_t a0 = k[0], a1 = k[1], a2 = k[2], a3 = k[3];
            k[0] = static_cast<uint8_t>(gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09));
            k[1] = static_cast<uint8_t>(gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d));
            k[2] = static_cast<uint8_t>(gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b));
            k[3] = static_cast<uint8_t>(gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e));
        }
}

void show_state(int round, const char* step, const uint8_t* s) {
    char lbl[32];
    snprintf(lbl, sizeof lbl, "round[%2d].%-8s", round, step);
    trace::out(std::string("          ") + trace::paint(trace::col::gray, lbl) + " " + to_hex(s, 16));
}

std::string word_hex(const uint8_t* w) { return to_hex(w, 4); }

} // namespace

uint8_t sbox(uint8_t x) { return T().s[x]; }
uint8_t inv_sbox(uint8_t x) { return T().inv[x]; }

Aes256::Aes256(const uint8_t key[kKeyLen], bool show) {
    std::memcpy(w_, key, kKeyLen);
    const std::string none = "-       ";
    auto row = [](int i, const std::string& cols, const uint8_t* wi) {
        char lbl[8];
        snprintf(lbl, sizeof lbl, "%3d", i);
        trace::out(std::string("      ") + lbl + "   " + cols + word_hex(wi));
    };
    if(show) {
        trace::out("    AES-256 KEY EXPANSION (FIPS-197 5.2): 32-byte key -> 60 words w[0..59] -> 15 round keys");
        trace::out("    (w[0..7] are the key itself; Rcon is used when i % 8 == 0, SubWord alone when i % 8 == 4)");
        trace::out(trace::paint(trace::col::gray,
                                "        i   temp      RotWord   SubWord   Rcon      ^Rcon     w[i-8]    w[i]"));
        std::string cols;
        for (int k = 0; k < 6; ++k) cols += none + "  ";
        for (int i = 0; i < kNk; ++i) row(i, cols, w_ + 4 * i);
    }
    uint8_t rcon = 0x01;
    for (int i = kNk; i < 4 * (kNr + 1); ++i) {
        uint8_t temp[4];
        std::memcpy(temp, w_ + 4 * (i - 1), 4);
        std::string c_temp = word_hex(temp), c_rot = none, c_sub = none, c_rcon = none, c_x = none;
        if (i % kNk == 0) {
            uint8_t first = temp[0];
            temp[0] = temp[1]; temp[1] = temp[2]; temp[2] = temp[3]; temp[3] = first;
            c_rot = word_hex(temp);
            for (auto& b : temp) b = T().s[b];
            c_sub = word_hex(temp);
            uint8_t rc[4] = {rcon, 0, 0, 0};
            c_rcon = word_hex(rc);
            temp[0] ^= rcon;
            c_x = word_hex(temp);
            rcon = xtime(rcon);
        } else if (i % kNk == 4) {
            for (auto& b : temp) b = T().s[b];
            c_sub = word_hex(temp);
        }
        for (int k = 0; k < 4; ++k) w_[4 * i + k] = static_cast<uint8_t>(w_[4 * (i - kNk) + k] ^ temp[k]);
        if (show)
            row(i, c_temp + "  " + c_rot + "  " + c_sub + "  " + c_rcon + "  " + c_x + "  " +
                       word_hex(w_ + 4 * (i - kNk)) + "  ", w_ + 4 * i);
    }
    if (show) {
        for (int r = 0; r <= kNr; ++r) {
            char lbl[48];
            snprintf(lbl, sizeof lbl, "round key %2d = w[%2d..%2d]", r, 4 * r, 4 * r + 3);
            trace::kv(6, lbl, to_hex(w_ + 16 * r, 16, true), trace::col::yellow);
        }
    }
}

Aes256::~Aes256() {
    volatile uint8_t* p = w_;
    for (size_t i = 0; i < sizeof w_; ++i) p[i] = 0;
}

void Aes256::encrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock], bool show) const {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    if (show) {
        trace::out("          AES-256 encrypt, 14 rounds (notation of FIPS-197 Appendix C):");
        trace::matrix(10, "input as 4x4 state (column-major):", s);
        show_state(0, "input", s);
        show_state(0, "k_sch", round_key(0));
    }
    add_round_key(s, round_key(0));
    for (int r = 1; r <= kNr; ++r) {
        if (show) show_state(r, "start", s);
        sub_bytes(s);
        if (show) show_state(r, "s_box", s);
        shift_rows(s);
        if (show) show_state(r, "s_row", s);
        if (r != kNr) {
            mix_columns(s);
            if (show) show_state(r, "m_col", s);
        }
        if (show) show_state(r, "k_sch", round_key(r));
        add_round_key(s, round_key(r));
    }
    if (show) {
        show_state(kNr, "output", s);
        trace::matrix(10, "output state:", s);
    }
    std::memcpy(out, s, 16);
}

void Aes256::decrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock], bool show) const {
    uint8_t s[16];
    std::memcpy(s, in, 16);
    if (show) {
        trace::out("          AES-256 decrypt (inverse cipher), 14 rounds (notation of FIPS-197 Appendix C):");
        trace::matrix(10, "input as 4x4 state (column-major):", s);
        show_state(0, "iinput", s);
        show_state(0, "ik_sch", round_key(kNr));
    }
    add_round_key(s, round_key(kNr));
    for (int r = 1; r <= kNr; ++r) {
        if (show) show_state(r, "istart", s);
        inv_shift_rows(s);
        if (show) show_state(r, "is_row", s);
        inv_sub_bytes(s);
        if (show) show_state(r, "is_box", s);
        if (show) show_state(r, "ik_sch", round_key(kNr - r));
        add_round_key(s, round_key(kNr - r));
        if (r != kNr) {
            if (show) show_state(r, "ik_add", s);
            inv_mix_columns(s);
        }
    }
    if (show) {
        show_state(kNr, "ioutput", s);
        trace::matrix(10, "output state:", s);
    }
    std::memcpy(out, s, 16);
}

} // namespace aes
