#pragma once

#include <string>
#include <vector>

#include "bytes.hpp"

namespace ns {

constexpr size_t kKeyLen = 32;

struct Field {
    std::string name;
    Bytes       value;
    std::string note;
};
void print_fields(const std::string& title, const std::vector<Field>& fields);

Bytes ask_long_term_key(const std::string& owner, const std::string& key_name);

struct Request { std::string id_a, id_b; uint64_t n1 = 0; };
Bytes              encode(const Request& m);
Request            decode_request(const Bytes& b);
std::vector<Field> fields(const Request& m);

struct Ticket { Bytes ks; std::string id_a; };
Bytes              encode(const Ticket& t);
Ticket             decode_ticket(const Bytes& b);
std::vector<Field> fields(const Ticket& t);

struct Reply { Bytes ks; std::string id_b; uint64_t n1 = 0; Bytes ticket; };
Bytes              encode(const Reply& m);
Reply              decode_reply(const Bytes& b);
std::vector<Field> fields(const Reply& m);

Bytes    encode_nonce(uint64_t n);
uint64_t decode_nonce(const Bytes& b);

struct ChatMsg { uint32_t seq = 0; std::string text; };
Bytes              encode(const ChatMsg& m);
ChatMsg            decode_chat(const Bytes& b);
std::vector<Field> fields(const ChatMsg& m);

void chat(int sock, const Bytes& ks, const std::string& me, const std::string& peer, const std::string& peer_addr);

std::string dec(uint64_t v);

} // namespace ns
