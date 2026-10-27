#pragma once
#include <string>
#include "bytes.hpp"

namespace trace {

extern int  level;  
extern bool quiet;  
extern bool color;  
extern bool step;    

namespace col {
constexpr const char* bold    = "1";
constexpr const char* red     = "1;31";
constexpr const char* green   = "32";
constexpr const char* yellow  = "33";
constexpr const char* blue    = "34";
constexpr const char* magenta = "35";
constexpr const char* cyan    = "36";
constexpr const char* gray    = "90";
}

void init(const std::string& party, const char* party_color);
inline bool on(int n) { return !quiet && level >= n; }

std::string paint(const char* code, const std::string& s);

void out(const std::string& s);                      
void banner(const std::string& title);               
void section(const std::string& title);              
void ok(const std::string& s);                        
void warn(const std::string& s);
void error(const std::string& s);                    
void kv(int indent, const std::string& label, const std::string& value, const char* code = nullptr);
void hexdump(int indent, const std::string& label, const Bytes& b, const char* code = nullptr);
void hexline(int indent, const std::string& label, const uint8_t* p, size_t n, const char* code = nullptr);
void matrix(int indent, const std::string& label, const uint8_t s[16]);
void prompt(const std::string& text);                
void input_done(const std::string& line);            
void pause(const std::string& what);                 
}