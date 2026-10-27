#pragma once
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;

struct CryptoError : std::runtime_error { using std::runtime_error::runtime_error; };
struct ProtocolError : std::runtime_error { using std::runtime_error::runtime_error; };

std::string to_hex(const uint8_t* p, size_t n, bool spaced = false);
inline std::string to_hex(const Bytes& b, bool spaced = false) { return to_hex(b.data(), b.size(), spaced); }
Bytes       from_hex(const std::string& hex);               
Bytes       to_bytes(const std::string& s);
std::string to_text(const Bytes& b);
std::string ascii(const uint8_t* p, size_t n);              

void     put_u8(Bytes& b, uint8_t v);
void     put_u16(Bytes& b, uint16_t v);
void     put_u32(Bytes& b, uint32_t v);
void     put_u64(Bytes& b, uint64_t v);
uint16_t get_u16(const uint8_t* p);
uint32_t get_u32(const uint8_t* p);
uint64_t get_u64(const uint8_t* p);
Bytes    be64(uint64_t v);

void     random_fill(uint8_t* out, size_t n);
Bytes    random_bytes(size_t n);
uint64_t random_u64();
void wipe(Bytes& b);
