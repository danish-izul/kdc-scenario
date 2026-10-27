#include <map>
#include <sstream>

#include "cbc.hpp"
#include "cli.hpp"
#include "net.hpp"
#include "ns.hpp"
#include "trace.hpp"

using namespace trace::col;

static const char* kUsage =
    "usage: kdc [--port 5000] [--users alice,bob]\n"
    "  --port PORT     TCP port to listen on (all interfaces)\n"
    "  --users LIST    comma-separated users to register; a passphrase is asked for each\n";

static std::string step_title(const std::string& s) { return trace::paint(cyan, ">> " + s); }

static void serve(int fd, const std::string& addr, const std::map<std::string, Bytes>& db) {
    trace::banner("FLOW 1 : A -> KDC   ID_A || ID_B || N1   (plaintext)");
    ns::Request req = ns::decode_request(net::expect(fd, net::REQ, addr));
    ns::print_fields("request received (plaintext: it contains no secret)", ns::fields(req));
    trace::out("    A = '" + req.id_a + "' wants to talk to B = '" + req.id_b + "'");

    auto a = db.find(req.id_a), b = db.find(req.id_b);
    if (a == db.end()) throw ProtocolError("unknown identity '" + req.id_a + "'");
    if (b == db.end()) throw ProtocolError("unknown identity '" + req.id_b + "'");
    if (req.id_a == req.id_b) throw ProtocolError("A and B must be different users");
    trace::ok("both identities are registered: K_A = key of '" + req.id_a + "', K_B = key of '" + req.id_b + "'");

    trace::pause("build and send flow 2");

    trace::banner("FLOW 2 : KDC -> A   E(K_A, [K_s || ID_B || N1 || E(K_B, [K_s || ID_A])])");
    Bytes ks = random_bytes(ns::kKeyLen);
    trace::section("generate a fresh random session key");
    trace::kv(4, "K_s", to_hex(ks), yellow);

    trace::out("");
    trace::out(step_title("step 2a: build the ticket for B and encrypt it with K_B (A cannot read it)"));
    ns::Ticket ticket{ks, req.id_a};
    ns::print_fields("ticket plaintext: K_s || ID_A", ns::fields(ticket));
    Bytes ticket_ct = cbc::seal(b->second, ns::encode(ticket), "K_B", "ticket for '" + req.id_b + "'");

    trace::out("");
    trace::out(step_title("step 2b: build the reply for A and encrypt it with K_A"));
    ns::Reply rep{ks, req.id_b, req.n1, ticket_ct};
    Bytes rep_pt = ns::encode(rep);
    ns::print_fields("flow 2 plaintext: K_s || ID_B || N1 || Ticket", ns::fields(rep));
    Bytes rep_ct = cbc::seal(a->second, rep_pt, "K_A", "flow 2 for '" + req.id_a + "'");

    net::send_frame(fd, net::REP, rep_ct, req.id_a + "@" + addr);
    trace::ok("flow 2 sent. '" + req.id_a + "' can decrypt it with K_A; the ticket inside is for '" + req.id_b +
              "'");
    wipe(ks);
    wipe(rep_pt);
}

int main(int argc, char** argv) {
    Cli cli(argc, argv, {"port", "users"}, kUsage);
    trace::init("KDC", yellow);
    try {
        uint16_t port = static_cast<uint16_t>(std::stoi(cli.get("port", "5000")));

        trace::banner("KDC SETUP : register the long-term keys shared with each user");
        trace::out("    Each user shares one secret key with the KDC. It is derived from a passphrase:");
        trace::out("    K_user = SHA-256(passphrase). The same passphrase must be typed on that user's machine.");
        std::map<std::string, Bytes> db;
        std::stringstream users(cli.get("users", "alice,bob"));
        for (std::string u; std::getline(users, u, ',');)
            if (!u.empty()) db[u] = ns::ask_long_term_key(u, "K_" + u);

        trace::section("KDC key database");
        for (const auto& [name, key] : db) trace::kv(4, name, to_hex(key), yellow);

        int lfd = net::listen_on(port);
        for (;;) {
            trace::banner("KDC listening on 0.0.0.0:" + std::to_string(port) + "  (waiting for flow 1)");
            std::string addr;
            int fd = net::accept_one(lfd, addr);
            trace::ok("connection from " + addr);
            try {
                serve(fd, addr, db);
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
