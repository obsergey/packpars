#include "Parser.h"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unordered_set>
#include <vector>

namespace packpars {

class CounterParser : public Parser {
    Metric metric_;
public:
    CounterParser(size_t order, const std::string& desc, Parser* parent) :
        Parser(parent), metric_{order, desc} {}        
    virtual void process(const u_char* , size_t) override {
        metric_.value++;
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        metrics.push_back(metric_);
    }
};

class SummaryLengthParser : public Parser {
    uint64_t length_{};
public:
    SummaryLengthParser(Parser* parent) : Parser(parent) {}
    virtual void process(const u_char* , size_t size) override {
        length_ += size;
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        metrics.push_back({1, "Summary length", length_ });
    }
};

class SizeParser : public Parser {
    std::vector<std::pair<size_t, Parser*>> ranges_;
public:
    SizeParser(Parser* parent) : Parser(parent), ranges_{
        { 0, new CounterParser(2, "Size <= 64", this) },
        { 65, new CounterParser(3, "Size 65 - 255", this) },
        { 256, new CounterParser(4, "Size 256 - 511", this) },
        { 512, new CounterParser(5, "Size 512 - 1023", this) },
        { 1024, new CounterParser(6, "Size 1024 - 1518", this) },
        { 1519, new CounterParser(7, "Size >= 1528", this) }
    } {}
    virtual void process(const u_char* packet, size_t size) override {
        const auto back = ranges_.end() - 1;
        for(auto range = ranges_.begin(); range != back; ++range) {
            if(range->first <= size && size < (range+1)->first) {
                range->second->process(packet, size);
                return;
            }
        }
        back->second->process(packet, size);
    }
};

class MacParser : public Parser {
    std::unordered_set<uint64_t> src_, dst_;
    static uint64_t macToUint64(const u_char* data) {
        return uint64_t(*reinterpret_cast<const uint32_t*>(data)) |
            (uint64_t(*reinterpret_cast<const uint16_t*>(data + 4)) << 32);
    }
public:
    MacParser(Parser* parent) : Parser(parent) {}
    virtual void process(const u_char* packet, size_t size) override {
        const ethhdr* header = reinterpret_cast<const ethhdr*>(packet);
        src_.insert(macToUint64(header->h_source));
        dst_.insert(macToUint64(header->h_dest));
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        metrics.push_back({14, "Unique source mac-address", src_.size() });
        metrics.push_back({15, "Unique destination mac-address", dst_.size() });
    }
};

class IpAddressParser : public Parser {
    std::unordered_set<uint32_t> src_, dst_;
public:
    IpAddressParser(Parser* parent) : Parser(parent) {}
    virtual void process(const u_char* packet, size_t size) override {
        const iphdr* header = reinterpret_cast<const iphdr*>(packet);
        src_.insert(header->saddr);
        dst_.insert(header->daddr);
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        metrics.push_back({16, "Unique source ip-address", src_.size() });
        metrics.push_back({17, "Unique destination ip-address", dst_.size() });
    }
};

template<typename T, typename Acc>
class ChecksumVerifier {
    Acc acc_{};
public:
    void append(T value) {
        acc_ += value;
    }
    bool verify() const {
        T sum = *(reinterpret_cast<const T*>(&acc_) + 1);
        sum += static_cast<T>(acc_);
        return sum ^ 0;
    }
};

class L3ChecksumParser : public Parser {
    uint64_t count_{};
    static bool verify(const u_char* header, size_t len) {
        ChecksumVerifier<uint8_t, uint16_t> verifier;
        for(size_t i = 0; i < len; ++i) {
            verifier.append(header[i]);
        }
        return verifier.verify(); 
    }
public:
    L3ChecksumParser(Parser* parent) : Parser(parent) {}
    virtual void process(const u_char* packet, size_t size) override {
        if(verify(packet, sizeof(iphdr))) {
            count_++;
        }
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        metrics.push_back({28, "Correct L3 checksum", count_ });
    }
};

class L4ProtocolParser : public Parser {
public:
    L4ProtocolParser(Parser* parent) : Parser(parent) {}
};

class IpParser : public Parser {
public:
    IpParser(Parser* parent) : Parser(parent) {
        new CounterParser(8, "IPv4", this);
        new IpAddressParser(this);
        new L3ChecksumParser(this);
        new L4ProtocolParser(this);
    }
    void process(const u_char* packet, size_t size) override {
        if(size >= sizeof(iphdr)) {
            Parser::process(packet, size);
        }
    }
};

class L3ProtocolParser : public Parser {
    std::vector<std::pair<uint16_t, Parser*>> protos_;
public:
    L3ProtocolParser(Parser* parent) : Parser(parent), protos_{
        { ETH_P_IP, new IpParser(this) },
        { 0, new CounterParser(9, "Non-IPv4", this) }
    } {}
    virtual void process(const u_char* packet, size_t size) override {
        const auto other = protos_.end() - 1;
        const uint16_t curproto = ntohs(reinterpret_cast<const ethhdr*>(packet)->h_proto);
        for(auto proto = protos_.begin(); proto != other; ++proto) {
            if(proto->first == curproto) {
                proto->second->process(packet + sizeof(ethhdr), size - sizeof(ethhdr));
                return;
            }
        }
        other->second->process(packet + sizeof(ethhdr), size - sizeof(ethhdr));
    }
};

class EtherParser : public Parser {
public:
    EtherParser(Parser* parent = nullptr) : Parser(parent) {
        new CounterParser(0, "Total count", this);
        new SummaryLengthParser(this);
        new SizeParser(this);
        new MacParser(this);
        new L3ProtocolParser(this);
    }
    virtual void process(const u_char* packet, size_t size) override {
        if(size >= sizeof(ethhdr)) {
            Parser::process(packet, size);
        }
    }
};

std::unique_ptr<Parser> Parser::common() {
    return std::unique_ptr<Parser>(new EtherParser());
}

Parser::Parser(Parser* parent) : parent_(parent) {
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

void Parser::process(const u_char* packet, size_t size) {
    for(Parser* child : children_) {
        child->process(packet, size);
    }
}

void Parser::metrics(std::list<Metric>& metrics) const {
    for(const Parser* child : children_) {
        child->metrics(metrics);
    }
}

} // namespace packpars