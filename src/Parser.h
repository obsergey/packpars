#pragma once
#include "Metric.h"
#include <memory>
#include <list>

namespace packpars {

class Parser {
    std::list<Parser*> children_;
    Parser* parent_;
public:
    static std::unique_ptr<Parser> common();
    explicit Parser(Parser* parent = nullptr);
    virtual ~Parser();
    Parser(const Parser&) = delete;
    Parser& operator=(const Parser&) = delete;
    virtual void process(const u_char* packet, size_t size);
    virtual void metrics(std::list<Metric>& metrics) const; 
};

} // namespace packpars