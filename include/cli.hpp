#pragma once
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <unistd.h>
#include <vector>
#include "trace.hpp"

class Cli {
public:
    Cli(int argc, char** argv, const std::vector<std::string>& valued, const std::string& usage) {
        trace::color = isatty(STDOUT_FILENO);
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "-v") {
                trace::level = std::max(trace::level, 1);
            } else if (a == "-vv") {
                trace::level = 2;
            } else if (a == "--step") {
                trace::step = true;
            } else if (a == "--no-color") {
                trace::color = false;
            } else if (a == "--color") {
                trace::color = true;
            } else if (a == "-h" || a == "--help") {
                std::cout << usage << common_help;
                std::exit(0);
            } else if (a.rfind("--", 0) == 0 &&
                       std::find(valued.begin(), valued.end(), a.substr(2)) != valued.end()) {
                if (i + 1 >= argc) fail("option " + a + " needs a value", usage);
                opt_[a.substr(2)] = argv[++i];
            } else {
                fail("unknown option '" + a + "'", usage);
            }
        }
    }

    std::string get(const std::string& name, const std::string& def) const {
        auto it = opt_.find(name);
        return it == opt_.end() ? def : it->second;
    }

private:
    static constexpr const char* common_help =
        "common options:\n"
        "  -v           also show every CBC block (P_i XOR C_{i-1} -> AES -> C_i) and full frames\n"
        "  -vv          also show every AES round, the AES key expansion and SHA-256 rounds\n"
        "  --step       wait for ENTER before each protocol flow (for presenting)\n"
        "  --no-color   disable ANSI colours (--color forces them on)\n";

    [[noreturn]] static void fail(const std::string& msg, const std::string& usage) {
        std::cerr << "error: " << msg << "\n\n" << usage << common_help;
        std::exit(2);
    }

    std::map<std::string, std::string> opt_;
};
