#include "cbc.hpp"
#include "cli.hpp"
#include "net.hpp"
#include "ns.hpp"
#include "trace.hpp"

using namespace trace::col;

static const char* kUsage =
    "usage: bob [--id bob] [--port 6000]\n"
    "  --id NAME       my identity ID_B (must be registered at the KDC)\n"
    "  --port PORT     TCP port to listen on (all interfaces)\n";

static void session(int fd, const std::string& addr, const std::string& me, const Bytes& kb) {
    trace::banner("FLOW 3 : A -> B   E(K_B, [K_s || ID_A])   (the ticket)");
    Bytes ticket_pt = cbc::open(kb, net::expect(fd, net::TICKET, addr), "K_B", "ticket (flow 3)");
    ns::Ticket t = ns::decode_ticket(ticket_pt);
    ns::print_fields("ticket plaintext: K_s || ID_A", ns::fields(t));
    trace::ok("decrypted with K_B -> the ticket was made by the KDC (only the KDC also knows K_B)");
    trace::ok("the KDC says: the peer is '" + t.id_a + "', session key K_s = " + to_hex(t.ks).substr(0, 16) + "...");
    trace::out("    But anyone could replay an old ticket, so I challenge the sender (flows 4-5).");
    const std::string peer = t.id_a, tag = t.id_a + "@" + addr;
    wipe(ticket_pt);

    trace::pause("send the challenge (flow 4)");

    trace::banner("FLOW 4 : B -> A   E(K_s, [N2])");
    uint64_t n2 = random_u64();
    trace::kv(4, "fresh random nonce N2", to_hex(be64(n2)) + " (= " + ns::dec(n2) + ")", magenta);
    Bytes chal_pt = ns::encode_nonce(n2);
    ns::print_fields("flow 4 plaintext", {{"N2", chal_pt, "= " + ns::dec(n2)}});
    net::send_frame(fd, net::CHAL, cbc::seal(t.ks, chal_pt, "K_s", "flow 4"), tag);

    trace::banner("FLOW 5 : A -> B   E(K_s, [f(N2)]),  f(N2) = N2 - 1");
    Bytes resp_pt = cbc::open(t.ks, net::expect(fd, net::RESP, tag), "K_s", "flow 5 from " + peer);
    uint64_t got = ns::decode_nonce(resp_pt);
    ns::print_fields("flow 5 plaintext", {{"N2-1", resp_pt, "= " + ns::dec(got)}});
    trace::section("check on flow 5");
    trace::kv(4, "expected N2 - 1", ns::dec(n2 - 1));
    trace::kv(4, "received", ns::dec(got));
    if (got != n2 - 1) throw ProtocolError("f(N2) is wrong: the sender does not hold K_s");
    trace::ok("f(N2) = N2 - 1 is correct -> '" + peer + "' holds K_s and this session is fresh");
    net::send_frame(fd, net::OK, {}, tag);

    ns::chat(fd, t.ks, me, peer, tag);
    wipe(t.ks);
}

int main(int argc, char** argv) {
    Cli cli(argc, argv, {"id", "port"}, kUsage);
    trace::init("BOB", magenta);
    try {
        const std::string me = cli.get("id", "bob");
        uint16_t port = static_cast<uint16_t>(std::stoi(cli.get("port", "6000")));

        trace::banner("BOB SETUP : I am B = '" + me + "'");
        Bytes kb = ns::ask_long_term_key(me, "K_B");

        int lfd = net::listen_on(port);
        for (;;) {
            trace::banner(me + " listening on 0.0.0.0:" + std::to_string(port) + "  (waiting for flow 3)");
            std::string addr;
            int fd = net::accept_one(lfd, addr);
            trace::ok("connection from " + addr);
            try {
                session(fd, addr, me, kb);
            } catch (const net::PeerError& e) {
                trace::error(e.what());
            } catch (const std::exception& e) {
                trace::error(e.what());
                net::send_error(fd, e.what(), addr);
            }
            net::close_fd(fd);
        }
    } catch (const std::exception& e) {
        trace::error(e.what());
        return 1;
    }
}
