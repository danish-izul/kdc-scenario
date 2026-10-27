#pragma once
#include <string>

namespace io {
bool read_line(std::string& out);    
bool pop_line(std::string& out);    
bool fill();                         
bool at_eof();                      
bool interactive();                 
std::string ask(const std::string& question);
}