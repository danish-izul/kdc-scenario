#include "bytes.hpp"

#include <fstream>

std::string to_hex(const uint8_t* p, size_t n, bool spaced) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (spaced && i) s += ' ';
        s += digits[p[i] >> 4];
        s += digits[p[i] & 0x0f];
    }
    return s;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

Bytes from_hex(const std::string& hex) {
    std::string h;
    for (char c : hex)
        if (c != ' ') h += c;
    if (h.size() % 2) throw std::invalid_argument("odd number of hex digits");
    Bytes out(h.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = hex_val(h[2 * i]), lo = hex_val(h[2 * i + 1]);
        if (hi < 0 || lo < 0) throw std::invalid_argument("bad hex digit");
        out[i] = static_cast<uint8_t>(hi << 4 | lo);
    }
    return out;
}

Bytes to_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
std::string to_text(const Bytes& b) { return std::string(b.begin(), b.end()); }

std::string ascii(const uint8_t* p, size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) s += (p[i] >= 0x20 && p[i] < 0x7f) ? static_cast<char>(p[i]) : '.';
    return s;
}

void put_u8(Bytes& b, uint8_t v) { b.push_back(v); }
void put_u16(Bytes& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v));
}
void put_u32(Bytes& b, uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put_u64(Bytes& b, uint64_t v) {
    for (int i = 7; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
uint16_t get_u16(const uint8_t* p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
uint32_t get_u32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) << 24 | static_cast<uint32_t>(p[1]) << 16 |
           static_cast<uint32_t>(p[2]) << 8 | p[3];
}
uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = v << 8 | p[i];
    return v;
}
Bytes be64(uint64_t v) {
    Bytes b;
    put_u64(b, v);
    return b;
}

void random_fill(uint8_t* out, size_t n) {
    std::ifstream f("/dev/urandom", std::ios::binary);
    if (!f.read(reinterpret_cast<char*>(out), static_cast<std::streamsize>(n)))
        throw std::runtime_error("cannot read /dev/urandom");
}
Bytes random_bytes(size_t n) {
    Bytes b(n);
    random_fill(b.data(), n);
    return b;
}
uint64_t random_u64() {
    uint8_t b[8];
    random_fill(b, 8);
    return get_u64(b);
}

void wipe(Bytes& b) {
    volatile uint8_t* p = b.data();
    for (size_t i = 0; i < b.size(); ++i) p[i] = 0;
    b.clear();
}
