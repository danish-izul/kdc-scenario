#include "io.hpp"
#include <cerrno>
#include <unistd.h>
#include "trace.hpp"

namespace io {

static std::string g_buf;
static bool g_eof = false;

bool fill() {
    char tmp[4096];
    for (;;) {
        ssize_t n = ::read(STDIN_FILENO, tmp, sizeof tmp);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            g_eof = true;
            return false;
        }
        g_buf.append(tmp, static_cast<size_t>(n));
        return true;
    }
}

bool pop_line(std::string& out) {
    size_t nl = g_buf.find('\n');
    if (nl == std::string::npos) {
        if (!g_eof || g_buf.empty()) return false;
        out.swap(g_buf);                 // last line without a trailing newline
        g_buf.clear();
    } else {
        out = g_buf.substr(0, nl);
        g_buf.erase(0, nl + 1);
    }
    if (!out.empty() && out.back() == '\r') out.pop_back();
    return true;
}

bool read_line(std::string& out) {
    while (!pop_line(out)) {
        if (g_eof) return false;
        fill();
    }
    return true;
}

bool at_eof() { return g_eof && g_buf.empty(); }
bool interactive() { return isatty(STDIN_FILENO); }

std::string ask(const std::string& question) {
    trace::prompt(question);
    std::string line;
    if (!read_line(line)) throw std::runtime_error("unexpected end of input");
    trace::input_done(line);
    return line;
}

}