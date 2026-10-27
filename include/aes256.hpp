#pragma once

#include <cstddef>
#include <cstdint>

namespace aes
{
    constexpr size_t kBlock = 16;
    constexpr size_t kKeyLen = 32;
    constexpr int kNk = 8;
    constexpr int kNr = 14;

    uint8_t gf_mul(uint8_t a, uint8_t b);
    uint8_t sbox(uint8_t x);
    uint8_t inv_sbox(uint8_t x);

    class Aes256
    {
    private:
        uint8_t w_[16 * (kNr + 1)];
    public:
        explicit Aes256(const uint8_t key[kKeyLen], bool show = false /*verbose*/);
        ~Aes256();
        Aes256(const Aes256&) = delete;
        Aes256& operator=(const Aes256&) = delete;

        void encrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock], bool show = false) const;
        void decrypt_block(const uint8_t in[kBlock], uint8_t out[kBlock], bool show = false) const;

        const uint8_t* round_key(int round) const { return w_ + 16 * round; }
    };

} // namespace aes
