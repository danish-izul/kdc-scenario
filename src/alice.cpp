#include "cbc.hpp"
#include "cli.hpp"
#include "net.hpp"
#include "ns.hpp"
#include "trace.hpp"

using namespace trace::col;

static const char* kUsage =
    "usage: alice [--id alice] [--peer bob] [--kdc 127.0.0.1:5000] [--bob 127.0.0.1:6000]\n"
    "  --id NAME       my identity ID_A (must be registered at the KDC)\n"
    "  --peer NAME     identity ID_B of the user I want to talk to\n"
    "  --kdc IP:PORT   address of the KDC\n"
    "  --bob IP:PORT   address of the peer\n";

int main(int argc, char** argv) {
    Cli cli(argc, argv, {"id", "peer", "kdc", "bob"}, kUsage);
    trace::init("ALICE", cyan);
    int kdc = -1, bob = -1;
    try {
        const std::string me = cli.get("id", "alice");
        const std::string peer = cli.get("peer", "bob");
        const net::Addr kdc_addr = net::parse_addr(cli.get("kdc", "127.0.0.1:5000"));
        const net::Addr bob_addr = net::parse_addr(cli.get("bob", "127.0.0.1:6000"));
        const std::string kdc_tag = "KDC@" + kdc_addr.str(), bob_tag = peer + "@" + bob_addr.str();

        trace::banner("ALICE SETUP : I am A = '" + me + "', I want to talk to B = '" + peer + "'");
        Bytes ka = ns::ask_long_term_key(me, "K_A");

        trace::pause("start flow 1");

        trace::banner("FLOW 1 : A -> KDC   ID_A || ID_B || N1   (plaintext)");
        ns::Request req{me, peer, random_u64()};
        trace::kv(4, "fresh random nonce N1", to_hex(be64(req.n1)) + " (= " + ns::dec(req.n1) + ")", cyan);
        ns::print_fields("flow 1 message (sent in the clear: no secret inside)", ns::fields(req));
        kdc = net::connect_to(kdc_addr);
        trace::ok("connected to KDC " + kdc_addr.str());
        net::send_frame(kdc, net::REQ, ns::encode(req), kdc_tag);

        trace::banner("FLOW 2 : KDC -> A   E(K_A, [K_s || ID_B || N1 || E(K_B, [K_s || ID_A])])");
        Bytes rep_ct = net::expect(kdc, net::REP, kdc_tag);
        net::close_fd(kdc);
        kdc = -1;
        Bytes rep_pt = cbc::open(ka, rep_ct, "K_A", "flow 2 from KDC");
        ns::Reply rep = ns::decode_reply(rep_pt);
        ns::print_fields("flow 2 plaintext: K_s || ID_B || N1 || Ticket", ns::fields(rep));

        trace::section("checks on flow 2");
        if (rep.n1 != req.n1)
            throw ProtocolError("N1 mismatch (sent " + ns::dec(req.n1) + ", got " + ns::dec(rep.n1) +
                                "): replay of an old KDC reply?");
        trace::ok("N1 matches the nonce I sent -> this reply is fresh, not a replay");
        if (rep.id_b != peer) throw ProtocolError("reply is for '" + rep.id_b + "', not '" + peer + "'");
        trace::ok("ID_B = '" + rep.id_b + "' is the peer I asked for");
        trace::ok("decrypted with K_A -> it really comes from the KDC (only the KDC also knows K_A)");
        trace::kv(4, "session key K_s", to_hex(rep.ks), yellow);
        trace::out("    The ticket is encrypted with K_B. I cannot read or change it; I just forward it.");
        wipe(ka);
        wipe(rep_pt);

        trace::pause("send flow 3 to " + peer);

        trace::banner("FLOW 3 : A -> B   E(K_B, [K_s || ID_A])   (forward the ticket)");
        bob = net::connect_to(bob_addr);
        trace::ok("connected to " + peer + " at " + bob_addr.str());
        trace::hexdump(4, "ticket (opaque to me)", rep.ticket, red);
        net::send_frame(bob, net::TICKET, rep.ticket, bob_tag);

        trace::banner("FLOW 4 : B -> A   E(K_s, [N2])   (B's challenge)");
        Bytes chal_pt = cbc::open(rep.ks, net::expect(bob, net::CHAL, bob_tag), "K_s", "flow 4 from " + peer);
        uint64_t n2 = ns::decode_nonce(chal_pt);
        ns::print_fields("flow 4 plaintext", {{"N2", chal_pt, "= " + ns::dec(n2)}});
        trace::ok(peer + " can encrypt with K_s -> " + peer + " decrypted the ticket, so " + peer +
                  " really holds K_B");

        trace::pause("answer the challenge (flow 5)");

        trace::banner("FLOW 5 : A -> B   E(K_s, [f(N2)]),  f(N2) = N2 - 1");
        uint64_t f = n2 - 1;
        trace::kv(4, "N2", ns::dec(n2));
        trace::kv(4, "f(N2) = N2 - 1", ns::dec(f), cyan);
        Bytes resp_pt = ns::encode_nonce(f);
        ns::print_fields("flow 5 plaintext", {{"N2-1", resp_pt, "= " + ns::dec(f)}});
        net::send_frame(bob, net::RESP, cbc::seal(rep.ks, resp_pt, "K_s", "flow 5"), bob_tag);
        net::expect(bob, net::OK, bob_tag);
        trace::ok(peer + " accepted f(N2): both sides now share the session key K_s");

        ns::chat(bob, rep.ks, me, peer, bob_tag);
        wipe(rep.ks);
        net::close_fd(bob);
        return 0;
    } catch (const net::PeerError& e) {
        trace::error(e.what());
    } catch (const std::exception& e) {
        trace::error(e.what());
        if (bob >= 0) net::send_error(bob, e.what(), "peer");
    }
    net::close_fd(kdc);
    net::close_fd(bob);
    return 1;
}
