#include "net.hpp"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "trace.hpp"

namespace net {
static constexpr uint32_t kMaxFrame = 1 << 20;

const char* type_name(uint8_t t) {
    switch (t) {
    case REQ:    return "REQ (flow 1)";
    case REP:    return "REP (flow 2)";
    case TICKET: return "TICKET (flow 3)";
    case CHAL:   return "CHAL (flow 4)";
    case RESP:   return "RESP (flow 5)";
    case OK:     return "OK";
    case CHAT:   return "CHAT";
    case BYE:    return "BYE";
    case ERR:    return "ERROR";
    default:     return "UNKNOWN";
    }
}

static std::string sys_err(const std::string& what) { return what + ": " + std::strerror(errno); }

Addr parse_addr(const std::string& s) {
    size_t colon = s.rfind(':');
    if (colon == std::string::npos) throw std::invalid_argument("address must be IP:PORT, got '" + s + "'");
    Addr a;
    a.ip = s.substr(0, colon);
    if (a.ip == "localhost") a.ip = "127.0.0.1";
    in_addr tmp{};
    if (inet_pton(AF_INET, a.ip.c_str(), &tmp) != 1)
        throw std::invalid_argument("'" + a.ip + "' is not an IPv4 address");
    long port = std::strtol(s.c_str() + colon + 1, nullptr, 10);
    if (port <= 0 || port > 65535) throw std::invalid_argument("bad port in '" + s + "'");
    a.port = static_cast<uint16_t>(port);
    return a;
}

int listen_on(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw NetError(sys_err("socket"));
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) {
        ::close(fd);
        throw NetError(sys_err("bind port " + std::to_string(port)));
    }
    if (::listen(fd, 8) < 0) {
        ::close(fd);
        throw NetError(sys_err("listen"));
    }
    return fd;
}

int accept_one(int listener, std::string& peer) {
    sockaddr_in a{};
    socklen_t len = sizeof a;
    int fd;
    do {
        fd = ::accept(listener, reinterpret_cast<sockaddr*>(&a), &len);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) throw NetError(sys_err("accept"));
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &a.sin_addr, ip, sizeof ip);
    peer = std::string(ip) + ":" + std::to_string(ntohs(a.sin_port));
    return fd;
}

int connect_to(const Addr& addr) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw NetError(sys_err("socket"));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(addr.port);
    inet_pton(AF_INET, addr.ip.c_str(), &a.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) {
        std::string msg = sys_err("connect to " + addr.str());
        ::close(fd);
        throw NetError(msg);
    }
    return fd;
}

void close_fd(int fd) {
    if (fd >= 0) ::close(fd);
}

static void send_all(int fd, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t k = ::send(fd, p, n, MSG_NOSIGNAL);
        if (k < 0) {
            if (errno == EINTR) continue;
            throw NetError(sys_err("send"));
        }
        p += k;
        n -= static_cast<size_t>(k);
    }
}

static bool recv_all(int fd, uint8_t* p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t k = ::recv(fd, p + got, n - got, 0);
        if (k < 0) {
            if (errno == EINTR) continue;
            throw NetError(sys_err("recv"));
        }
        if (k == 0) {
            if (got == 0) return false;
            throw NetError("connection closed in the middle of a frame");
        }
        got += static_cast<size_t>(k);
    }
    return true;
}

static void show_wire(bool sending, uint8_t type, const Bytes& frame, const std::string& peer) {
    if (!trace::on(0)) return;
    std::string head = sending ? "[wire] SEND -> " + peer : "[wire] RECV <- " + peer;
    trace::out(trace::paint(trace::col::blue, head) + "  type=" + type_name(type) + ", " +
               std::to_string(frame.size()) + " bytes = len(4) | type(1) | payload(" +
               std::to_string(frame.size() - 5) + ")");
    if (trace::on(1)) {
        trace::hexdump(4, "frame bytes on the wire", frame, trace::col::blue);
    } else {
        size_t n = frame.size() < 24 ? frame.size() : 24;
        trace::out("    " + trace::paint(trace::col::blue, to_hex(frame.data(), n, true)) +
                   (frame.size() > n ? " ... (-v shows all)" : ""));
    }
}

void send_frame(int fd, uint8_t type, const Bytes& payload, const std::string& peer) {
    Bytes frame;
    put_u32(frame, static_cast<uint32_t>(payload.size() + 1));
    put_u8(frame, type);
    frame.insert(frame.end(), payload.begin(), payload.end());
    show_wire(true, type, frame, peer);
    send_all(fd, frame.data(), frame.size());
}

bool recv_frame(int fd, uint8_t& type, Bytes& payload, const std::string& peer) {
    uint8_t hdr[4];
    if (!recv_all(fd, hdr, 4)) return false;
    uint32_t len = get_u32(hdr);
    if (len < 1 || len > kMaxFrame) throw NetError("bad frame length " + std::to_string(len));
    Bytes body(len);
    if (!recv_all(fd, body.data(), len)) throw NetError("connection closed in the middle of a frame");
    type = body[0];
    payload.assign(body.begin() + 1, body.end());
    Bytes frame(hdr, hdr + 4);
    frame.insert(frame.end(), body.begin(), body.end());
    show_wire(false, type, frame, peer);
    return true;
}

Bytes expect(int fd, uint8_t want, const std::string& peer) {
    uint8_t type;
    Bytes payload;
    if (!recv_frame(fd, type, payload, peer)) throw NetError(peer + " closed the connection");
    if (type == ERR) throw PeerError(peer + " rejected us: " + to_text(payload));
    if (type != want)
        throw ProtocolError(std::string("expected ") + type_name(want) + " but got " + type_name(type));
    return payload;
}

void send_error(int fd, const std::string& reason, const std::string& peer) {
    try {
        send_frame(fd, ERR, to_bytes(reason), peer);
    } catch (...) {
    }
}

}  
