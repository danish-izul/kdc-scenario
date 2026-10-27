#include "cbc.hpp"

#include <cstring>
#include <set>

#include "aes256.hpp"
#include "trace.hpp"

namespace cbc {

using trace::col::cyan;
using trace::col::green;
using trace::col::red;
using trace::col::yellow;

static std::string hex8(uint8_t v) { return "0x" + to_hex(&v, 1); }

Bytes pkcs7_pad(const Bytes& in) {
    const size_t n = aes::kBlock - in.size() % aes::kBlock;
    Bytes out(in);
    out.insert(out.end(), n, static_cast<uint8_t>(n));
    return out;
}

Bytes pkcs7_unpad(const Bytes& in) {
    if (in.empty() || in.size() % aes::kBlock)
        throw CryptoError("bad padding: length is not a positive multiple of 16");
    const uint8_t n = in.back();
    if (n == 0 || n > aes::kBlock)
        throw CryptoError("bad padding: last byte " + hex8(n) + " is not in 0x01..0x10 (wrong key or tampered data)");
    for (size_t i = in.size() - n; i < in.size(); ++i)
        if (in[i] != n)
            throw CryptoError("bad padding: expected " + std::to_string(n) + " bytes of " + hex8(n) +
                              " (wrong key or tampered data)");
    return Bytes(in.begin(), in.end() - n);
}

static std::set<Bytes> g_shown_keys;
static void check_key(const Bytes& key) {
    if (key.size() != aes::kKeyLen) throw std::invalid_argument("AES-256 key must be 32 bytes");
}
static bool show_schedule(const Bytes& key, bool show) {
    if (!show || !trace::on(2) || g_shown_keys.count(key)) return false;
    g_shown_keys.insert(key);
    return true;
}

Bytes encrypt(const Bytes& key, const uint8_t iv[16], const Bytes& plaintext, bool show) {
    check_key(key);
    if (plaintext.size() % aes::kBlock) throw std::invalid_argument("CBC input must be a multiple of 16 bytes");
    aes::Aes256 cipher(key.data(), show_schedule(key, show));
    const size_t blocks = plaintext.size() / aes::kBlock;
    Bytes out(plaintext.size());
    uint8_t prev[16], x[16];
    std::memcpy(prev, iv, 16);
    for (size_t b = 0; b < blocks; ++b) {
        const uint8_t* p = &plaintext[16 * b];
        uint8_t* c = &out[16 * b];
        for (int i = 0; i < 16; ++i) x[i] = p[i] ^ prev[i];
        const bool blk = show && trace::on(1);
        if (blk) {
            const std::string i = std::to_string(b + 1), j = std::to_string(b);
            trace::out("      Block " + i + "/" + std::to_string(blocks) + ":");
            trace::hexline(8, "P_" + i, p, 16, green);
            trace::hexline(8, b == 0 ? "C_0 (= IV)" : "C_" + j, prev, 16);
            trace::hexline(8, "P_" + i + " XOR C_" + j, x, 16);
        }
        cipher.encrypt_block(x, c, show && trace::on(2));
        if (blk) trace::hexline(8, "C_" + std::to_string(b + 1) + " = AES_K(.)", c, 16, red);
        std::memcpy(prev, c, 16);
    }
    return out;
}

Bytes decrypt(const Bytes& key, const uint8_t iv[16], const Bytes& ciphertext, bool show) {
    check_key(key);
    if (ciphertext.empty() || ciphertext.size() % aes::kBlock)
        throw CryptoError("ciphertext length " + std::to_string(ciphertext.size()) +
                          " is not a positive multiple of 16");
    aes::Aes256 cipher(key.data(), show_schedule(key, show));
    const size_t blocks = ciphertext.size() / aes::kBlock;
    Bytes out(ciphertext.size());
    uint8_t prev[16], x[16];
    std::memcpy(prev, iv, 16);
    for (size_t b = 0; b < blocks; ++b) {
        const uint8_t* c = &ciphertext[16 * b];
        uint8_t* p = &out[16 * b];
        const bool blk = show && trace::on(1);
        const std::string i = std::to_string(b + 1), j = std::to_string(b);
        if (blk) {
            trace::out("      Block " + i + "/" + std::to_string(blocks) + ":");
            trace::hexline(8, "C_" + i, c, 16, red);
        }
        cipher.decrypt_block(c, x, show && trace::on(2));
        for (int k = 0; k < 16; ++k) p[k] = x[k] ^ prev[k];
        if (blk) {
            trace::hexline(8, "AES^-1_K(C_" + i + ")", x, 16);
            trace::hexline(8, b == 0 ? "C_0 (= IV)" : "C_" + j, prev, 16);
            trace::hexline(8, "P_" + i + " = D XOR C_" + j, p, 16, green);
        }
        std::memcpy(prev, c, 16);
    }
    return out;
}

Bytes seal(const Bytes& key, const Bytes& plaintext, const std::string& key_name, const std::string& what) {
    trace::section("AES-256-CBC ENCRYPT  " + what + "  with " + key_name);
    Bytes iv = random_bytes(16);
    trace::kv(4, "key " + key_name, to_hex(key), yellow);
    trace::kv(4, "IV (fresh random)", to_hex(iv), cyan);
    trace::hexdump(4, "plaintext", plaintext, green);

    Bytes padded = pkcs7_pad(plaintext);
    const uint8_t n = padded.back();
    trace::kv(4, "PKCS#7 padding", std::to_string(plaintext.size()) + " bytes + " + std::to_string(n) + " x " +
                                       hex8(n) + " = " + std::to_string(padded.size()) + " bytes = " +
                                       std::to_string(padded.size() / 16) + " block(s)");
    if (trace::on(1)) trace::hexdump(4, "padded plaintext", padded, green);
    if (trace::on(1)) trace::out("    CBC chaining: C_0 = IV, C_i = AES_K(P_i XOR C_{i-1})");

    Bytes ct = encrypt(key, iv.data(), padded, true);
    trace::hexdump(4, "ciphertext C_1..C_" + std::to_string(ct.size() / 16), ct, red);

    Bytes sealed(iv);
    sealed.insert(sealed.end(), ct.begin(), ct.end());
    trace::kv(4, "output", "IV || ciphertext = " + std::to_string(sealed.size()) + " bytes");
    wipe(padded);
    return sealed;
}

Bytes open(const Bytes& key, const Bytes& sealed, const std::string& key_name, const std::string& what) {
    trace::section("AES-256-CBC DECRYPT  " + what + "  with " + key_name);
    if (sealed.size() < 32 || sealed.size() % 16)
        throw CryptoError("sealed message of " + std::to_string(sealed.size()) +
                          " bytes cannot be IV || ciphertext (need 16 + 16k bytes)");
    Bytes iv(sealed.begin(), sealed.begin() + 16);
    Bytes ct(sealed.begin() + 16, sealed.end());
    trace::kv(4, "key " + key_name, to_hex(key), yellow);
    trace::kv(4, "IV (first 16 bytes)", to_hex(iv), cyan);
    trace::hexdump(4, "ciphertext", ct, red);
    if (trace::on(1)) trace::out("    CBC chaining: P_i = AES^-1_K(C_i) XOR C_{i-1}, C_0 = IV");

    Bytes padded = decrypt(key, iv.data(), ct, true);
    if (trace::on(1)) trace::hexdump(4, "padded plaintext", padded, green);
    const uint8_t n = padded.back();
    Bytes pt;
    try {
        pt = pkcs7_unpad(padded);
    } catch (const CryptoError& e) {
        throw CryptoError("decryption with " + key_name + " failed, " + e.what());
    }
    trace::kv(4, "PKCS#7 check", "last byte " + hex8(n) + " -> remove " + std::to_string(n) + " bytes, all equal " +
                                     hex8(n) + "  OK", green);
    trace::hexdump(4, "plaintext", pt, green);
    wipe(padded);
    return pt;
}

} // namespace cbc
