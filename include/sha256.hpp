#pragma once

#include "bytes.hpp"

namespace sha256 {

Bytes hash(const Bytes& msg, bool show = false);

} // namespace sha256
