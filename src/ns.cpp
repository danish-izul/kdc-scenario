#include "ns.hpp"

#include <cerrno>
#include <cstdio>
#include <poll.h>
#include <unistd.h>

#include "cbc.hpp"
#include "io.hpp"
#include "net.hpp"
#include "sha256.hpp"
#include "trace.hpp"

namespace ns {

using trace::col::bold;
using trace::col::green;
using trace::col::yellow;

std::string dec(uint64_t v) { return std::to_string(v); }

void print_fields(const std::string& title, const std::vector<Field>& fields) {
    trace::section(title);
    size_t total = 0;
    std::string layout;
    for (const auto& f : fields) {
        char head[64];
        snprintf(head, sizeof head, "    %-12s %3zu B  ", f.name.c_str(), f.value.size());
        std::string hex = f.value.size() > 32 ? to_hex(f.value.data(), 16) + "..." : to_hex(f.value);
        trace::out(head + hex + (f.note.empty() ? "" : "  " + trace::paint(bold, f.note)));
        total += f.value.size();
        layout += (layout.empty() ? "" : " | ") + f.name;
    }
    trace::out("    layout: " + layout + "  = " + std::to_string(total) + " bytes");
}

static Field id_len(const std::string& name, const std::string& id) {
    return {"len(" + name + ")", Bytes{static_cast<uint8_t>(id.size())}, ""};
}
static Field id_field(const std::string& name, const std::string& id) {
    return {name, to_bytes(id), "\"" + id + "\""};
}
static Field nonce_field(const std::string& name, uint64_t n) { return {name, be64(n), "= " + dec(n)}; }

Bytes ask_long_term_key(const std::string& owner, const std::string& key_name) {
    trace::section("Long-term key " + key_name + " of '" + owner + "' (known only to " + owner + " and the KDC)");
    std::string pass;
    for (;;) {
        pass = io::ask("Enter passphrase for '" + owner + "': ");
        if (!pass.empty()) break;
        trace::warn("passphrase must not be empty");
    }
    Bytes pb = to_bytes(pass);
    trace::kv(4, "passphrase", "\"" + pass + "\" (" + std::to_string(pb.size()) + " bytes)", bold);
    trace::out("    " + key_name + " = SHA-256(passphrase)  -> exactly 32 bytes = one AES-256 key");
    Bytes key = sha256::hash(pb, true);
    trace::kv(4, key_name, to_hex(key), yellow);
    wipe(pb);
    return key;
}

namespace {

void put_id(Bytes& b, const std::string& id) {
    if (id.empty() || id.size() > 255) throw ProtocolError("identity must be 1..255 bytes");
    put_u8(b, static_cast<uint8_t>(id.size()));
    b.insert(b.end(), id.begin(), id.end());
}

class Reader {
public:
    Reader(const Bytes& b, const char* what) : b_(b), what_(what) {}
    uint8_t u8() { need(1); return b_[pos_++]; }
    uint16_t u16() { need(2); uint16_t v = get_u16(&b_[pos_]); pos_ += 2; return v; }
    uint32_t u32() { need(4); uint32_t v = get_u32(&b_[pos_]); pos_ += 4; return v; }
    uint64_t u64() { need(8); uint64_t v = get_u64(&b_[pos_]); pos_ += 8; return v; }
    Bytes raw(size_t n) {
        need(n);
        Bytes v(b_.begin() + static_cast<long>(pos_), b_.begin() + static_cast<long>(pos_ + n));
        pos_ += n;
        return v;
    }
    std::string id() {
        size_t n = u8();
        if (n == 0) throw ProtocolError(std::string(what_) + ": empty identity");
        return to_text(raw(n));
    }
    std::string rest() { return to_text(raw(b_.size() - pos_)); }
    void end() const {
        if (pos_ != b_.size()) throw ProtocolError(std::string(what_) + ": unexpected trailing bytes");
    }

private:
    void need(size_t n) const {
        if (b_.size() - pos_ < n) throw ProtocolError(std::string(what_) + ": message too short / malformed");
    }
    const Bytes& b_;
    const char* what_;
    size_t pos_ = 0;
};

} // namespace

Bytes encode(const Request& m) {
    Bytes b;
    put_id(b, m.id_a);
    put_id(b, m.id_b);
    put_u64(b, m.n1);
    return b;
}
Request decode_request(const Bytes& b) {
    Reader r(b, "flow 1");
    Request m;
    m.id_a = r.id();
    m.id_b = r.id();
    m.n1 = r.u64();
    r.end();
    return m;
}
std::vector<Field> fields(const Request& m) {
    return {id_len("ID_A", m.id_a), id_field("ID_A", m.id_a), id_len("ID_B", m.id_b), id_field("ID_B", m.id_b),
            nonce_field("N1", m.n1)};
}

Bytes encode(const Ticket& t) {
    if (t.ks.size() != kKeyLen) throw ProtocolError("session key must be 32 bytes");
    Bytes b(t.ks);
    put_id(b, t.id_a);
    return b;
}
Ticket decode_ticket(const Bytes& b) {
    Reader r(b, "ticket");
    Ticket t;
    t.ks = r.raw(kKeyLen);
    t.id_a = r.id();
    r.end();
    return t;
}
std::vector<Field> fields(const Ticket& t) {
    return {{"K_s", t.ks, "session key"}, id_len("ID_A", t.id_a), id_field("ID_A", t.id_a)};
}

Bytes encode(const Reply& m) {
    if (m.ks.size() != kKeyLen) throw ProtocolError("session key must be 32 bytes");
    Bytes b(m.ks);
    put_id(b, m.id_b);
    put_u64(b, m.n1);
    put_u16(b, static_cast<uint16_t>(m.ticket.size()));
    b.insert(b.end(), m.ticket.begin(), m.ticket.end());
    return b;
}
Reply decode_reply(const Bytes& b) {
    Reader r(b, "flow 2");
    Reply m;
    m.ks = r.raw(kKeyLen);
    m.id_b = r.id();
    m.n1 = r.u64();
    m.ticket = r.raw(r.u16());
    r.end();
    return m;
}
std::vector<Field> fields(const Reply& m) {
    Bytes tl;
    put_u16(tl, static_cast<uint16_t>(m.ticket.size()));
    return {{"K_s", m.ks, "session key"},
            id_len("ID_B", m.id_b),
            id_field("ID_B", m.id_b),
            nonce_field("N1", m.n1),
            {"len(Ticket)", tl, ""},
            {"Ticket", m.ticket, "E(K_B, [K_s || ID_A])  (opaque without K_B)"}};
}

Bytes encode_nonce(uint64_t n) { return be64(n); }
uint64_t decode_nonce(const Bytes& b) {
    Reader r(b, "nonce");
    uint64_t n = r.u64();
    r.end();
    return n;
}

Bytes encode(const ChatMsg& m) {
    Bytes b;
    put_u32(b, m.seq);
    b.insert(b.end(), m.text.begin(), m.text.end());
    return b;
}
ChatMsg decode_chat(const Bytes& b) {
    Reader r(b, "chat");
    ChatMsg m;
    m.seq = r.u32();
    m.text = r.rest();
    return m;
}
std::vector<Field> fields(const ChatMsg& m) {
    Bytes s;
    put_u32(s, m.seq);
    return {{"seq", s, "= " + dec(m.seq)}, {"text", to_bytes(m.text), "\"" + m.text + "\""}};
}

void chat(int sock, const Bytes& ks, const std::string& me, const std::string& peer, const std::string& peer_addr) {
    trace::banner("SECURE CHAT  " + me + " <-> " + peer + "  (every message = E(K_s, seq || text))");
    trace::out("    Type a message and press ENTER to send it. Type /quit to end the session.");
    uint32_t seq_out = 0, last_in = 0;
    bool stdin_open = true;
    const std::string prompt = me + "> ";
    trace::prompt(prompt);

    for (;;) {
        std::string line;
        while (io::pop_line(line)) {
            trace::input_done(line);
            if (line == "/quit") {
                net::send_frame(sock, net::BYE, {}, peer_addr);
                trace::ok("chat closed by " + me);
                return;
            }
            if (!line.empty()) {
                ChatMsg m{++seq_out, line};
                trace::banner("CHAT #" + dec(m.seq) + "  " + me + " -> " + peer);
                print_fields("chat plaintext: seq || text", fields(m));
                Bytes sealed = cbc::seal(ks, encode(m), "K_s", "chat #" + dec(m.seq));
                net::send_frame(sock, net::CHAT, sealed, peer_addr);
            }
            trace::prompt(prompt);
        }
        if (stdin_open && io::at_eof()) {
            stdin_open = false;
            if (io::interactive()) { // Ctrl-D on the keyboard = /quit
                net::send_frame(sock, net::BYE, {}, peer_addr);
                trace::ok("chat closed by " + me + " (end of input)");
                return;
            }
            trace::out("    (input is not a terminal and has ended; still receiving until " + peer + " quits)");
        }

        pollfd fds[2] = {{sock, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};
        int n = ::poll(fds, stdin_open ? 2 : 1, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            throw net::NetError("poll failed");
        }
        if (stdin_open && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) io::fill();
        if (!(fds[0].revents & (POLLIN | POLLHUP | POLLERR))) continue;

        uint8_t type;
        Bytes payload;
        if (!net::recv_frame(sock, type, payload, peer_addr)) {
            trace::warn(peer + " closed the connection");
            return;
        }
        if (type == net::BYE) {
            trace::ok(peer + " ended the chat");
            return;
        }
        if (type == net::ERR) {
            trace::error(peer + " reported: " + to_text(payload));
            return;
        }
        if (type != net::CHAT) {
            trace::warn(std::string("ignoring unexpected frame ") + net::type_name(type));
            trace::prompt(prompt);
            continue;
        }
        trace::banner("CHAT  " + peer + " -> " + me);
        try {
            ChatMsg m = decode_chat(cbc::open(ks, payload, "K_s", "chat from " + peer));
            print_fields("chat plaintext: seq || text", fields(m));
            if (m.seq <= last_in) {
                trace::error("seq " + dec(m.seq) + " <= last seen " + dec(last_in) +
                             ": replayed or reordered message, rejected");
            } else {
                last_in = m.seq;
                trace::out("");
                trace::out(trace::paint(green, "  >>> " + peer + " says: ") + trace::paint(bold, m.text));
            }
        } catch (const std::exception& e) {
            trace::error(std::string("could not decrypt message: ") + e.what());
        }
        trace::prompt(prompt);
    }
}

} // namespace ns
