#include "Parser.h"

namespace packpars {

class CounterParser : public Parser {
    Metric metric_;
public:
    CounterParser(size_t order, const std::string& desc, Parser* parent = nullptr) :
        Parser(parent), metric_{order, desc} {}
        
    virtual void process(const u_char* , size_t) override {
        metric_.value++;
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        metrics.push_back(metric_);
    }
};

std::unique_ptr<Parser> Parser::common() {
    return std::unique_ptr<Parser>(new CounterParser(0, "Total count"));
}

Parser::Parser(Parser* parent) {
    if(parent_) {
        parent_->children_.push_back(this);
    }
}

Parser::~Parser() {
    if(parent_) {
        parent_->children_.remove(this);
    }
    // children_ list will be changed when children are deleted
    // iterate over copy of children_ list
    for(const Parser* child : std::list<Parser*>(children_)) {
        delete child;
    }
}

void Parser::metrics(std::list<Metric>& metrics) const {
    for(const Parser* child : children_) {
        child->metrics(metrics);
    }
}

} // namespace packpars