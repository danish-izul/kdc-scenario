#pragma once
#include <string>
#include "bytes.hpp"

namespace net {
enum Type : uint8_t {
    REQ    = 1,     
    REP    = 2,     
    TICKET = 3,    
    CHAL   = 4,     
    RESP   = 5,    
    OK     = 6,    
    CHAT   = 7,      
    BYE    = 8,      
    ERR    = 0x7f,  
};
const char* type_name(uint8_t t);

struct NetError  : std::runtime_error { using std::runtime_error::runtime_error; };
struct PeerError : std::runtime_error { using std::runtime_error::runtime_error; }; 
struct Addr {
    std::string ip;
    uint16_t    port;
    std::string str() const { return ip + ":" + std::to_string(port); }
};
Addr parse_addr(const std::string& s);         

int  listen_on(uint16_t port);               
int  accept_one(int listener, std::string& peer);
int  connect_to(const Addr& a);
void close_fd(int fd);
void  send_frame(int fd, uint8_t type, const Bytes& payload, const std::string& peer);
bool  recv_frame(int fd, uint8_t& type, Bytes& payload, const std::string& peer);   // false = peer closed
Bytes expect(int fd, uint8_t want, const std::string& peer);   // throws PeerError / ProtocolError / NetError
void  send_error(int fd, const std::string& reason, const std::string& peer);       // best effort

}