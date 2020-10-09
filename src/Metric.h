#pragma once
#include <string>

namespace packpars {

struct Metric {
    size_t order;
    std::string description;
    uint64_t value;
};

inline bool operator<(const Metric& lhs, const Metric& rhs) {
    return lhs.order < rhs.order;
}

} // namespace packpars