#include "trace.hpp"
#include <cstdio>
#include <iostream>
#include "io.hpp"

namespace trace {
int  level = 0;
bool quiet = false;
bool color = true;
bool step  = false;

static std::string g_tag = "[?]";
static const char* g_tag_color = col::bold;
static bool g_prompt_pending = false;     // a prompt is on screen without a newline
static constexpr size_t kLabelWidth = 22;
static constexpr size_t kBannerWidth = 78;

void init(const std::string& party, const char* party_color) {
    g_tag = "[" + party + "]";
    while (g_tag.size() < 7) g_tag += ' ';
    g_tag_color = party_color;
}

std::string paint(const char* code, const std::string& s) {
    if (!color || !code) return s;
    return std::string("\033[") + code + "m" + s + "\033[0m";
}

void out(const std::string& s) {
    if (quiet) return;
    if (g_prompt_pending) {
        std::cout << '\n';
        g_prompt_pending = false;
    }
    std::cout << paint(g_tag_color, g_tag) << ' ' << s << '\n' << std::flush;
}

void banner(const std::string& title) {
    if (quiet) return;
    std::string t = "==== " + title + " ";
    while (t.size() < kBannerWidth - 8) t += '=';
    out("");
    out(paint(col::bold, t));
}

void section(const std::string& title) {
    out("");
    out(paint(col::bold, "--- " + title));
}

void ok(const std::string& s)    { out(paint(col::green, "[OK]   ") + s); }
void warn(const std::string& s)  { out(paint(col::yellow, "[WARN] ") + s); }
void error(const std::string& s) { out(paint(col::red, "[FAIL] " + s)); }

static std::string pad(const std::string& s, size_t w) {
    std::string r = s;
    if (r.size() < w) r += ' ' + std::string(w - r.size() - 1, '.');
    return r;
}

void kv(int indent, const std::string& label, const std::string& value, const char* code) {
    out(std::string(indent, ' ') + pad(label, kLabelWidth) + ": " + paint(code, value));
}

void hexdump(int indent, const std::string& label, const Bytes& b, const char* code) {
    if (quiet) return;
    out(std::string(indent, ' ') + label + " (" + std::to_string(b.size()) + " bytes):");
    char off[20];
    for (size_t i = 0; i < b.size(); i += 16) {
        size_t n = b.size() - i < 16 ? b.size() - i : 16;
        std::string hex = to_hex(&b[i], n, true);
        hex += std::string(47 - hex.size(), ' ');
        snprintf(off, sizeof off, "%04zx", i);
        out(std::string(indent + 2, ' ') + paint(col::gray, off) + "  " + paint(code, hex) + "  |" +
            ascii(&b[i], n) + "|");
    }
    if (b.empty()) out(std::string(indent + 2, ' ') + "(empty)");
}

void hexline(int indent, const std::string& label, const uint8_t* p, size_t n, const char* code) {
    kv(indent, label, to_hex(p, n, true), code);
}

void matrix(int indent, const std::string& label, const uint8_t s[16]) {
    out(std::string(indent, ' ') + label);
    for (int r = 0; r < 4; ++r) {
        std::string row = "| ";
        for (int c = 0; c < 4; ++c) row += to_hex(&s[r + 4 * c], 1) + " ";
        out(std::string(indent + 2, ' ') + row + "|");
    }
}

void prompt(const std::string& text) {
    if (quiet) return;
    if (g_prompt_pending) std::cout << '\n';
    std::cout << paint(g_tag_color, g_tag) << ' ' << paint(col::bold, text) << std::flush;
    g_prompt_pending = true;
}

void input_done(const std::string& line) {
    if (quiet) return;
    if (g_prompt_pending && !io::interactive()) std::cout << line << '\n' << std::flush;
    g_prompt_pending = false;
}

void pause(const std::string& what) {
    if (!step) return;
    io::ask("(step) press ENTER to " + what + " ... ");
}

}