#pragma once
#include <string_view>
#include <string>

namespace packpars {

struct Metric {
    Metric(size_t ord, std::string_view desc, uint64_t val) :
        order(ord), description(desc), value(val) {}
    size_t order;
    std::string description;
    uint64_t value;
};

inline bool operator<(const Metric& lhs, const Metric& rhs) {
    return lhs.order < rhs.order;
}

} // namespace packpars