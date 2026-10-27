#pragma once

#include <string>

#include "bytes.hpp"

namespace cbc {

Bytes pkcs7_pad(const Bytes& in);
Bytes pkcs7_unpad(const Bytes& in);

Bytes encrypt(const Bytes& key, const uint8_t iv[16], const Bytes& plaintext, bool show = false);
Bytes decrypt(const Bytes& key, const uint8_t iv[16], const Bytes& ciphertext, bool show = false);

Bytes seal(const Bytes& key, const Bytes& plaintext, const std::string& key_name, const std::string& what);
Bytes open(const Bytes& key, const Bytes& sealed, const std::string& key_name, const std::string& what);

} // namespace cbc
