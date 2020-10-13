#include "Parser.h"
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <vector>

namespace packpars {

inline bool operator<(const std::pair<size_t, packpars::Parser*>& lhs, size_t rhs) {
    return lhs.first < rhs;
}

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
        { 64, new CounterParser(2, "Size <= 64", this) },
        { 255, new CounterParser(3, "Size 65 - 255", this) },
        { 511, new CounterParser(4, "Size 256 - 511", this) },
        { 1023, new CounterParser(5, "Size 512 - 1023", this) },
        { 1518, new CounterParser(6, "Size 1024 - 1518", this) },
        { std::numeric_limits<size_t>::max(), new CounterParser(7, "Size >= 1519", this) }
    } {}
    virtual void process(const u_char* packet, size_t size) override {
        std::lower_bound(ranges_.cbegin(), ranges_.cend(), size)->second->process(packet, size);
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
        metrics.push_back({14, "Unique src mac", src_.size() });
        metrics.push_back({15, "Unique dst mac", dst_.size() });
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
        metrics.push_back({16, "Unique src ip", src_.size() });
        metrics.push_back({17, "Unique dst ip", dst_.size() });
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
        sum = ~sum;
        return sum == 0;
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
        metrics.push_back({27, "Correct L3 checksum", count_ });
    }
};

class L4ChecksumParser : public Parser {
    uint64_t count_;
    static bool verify(const iphdr* header, const u_char* data, size_t size) {
        ChecksumVerifier<uint16_t, uint32_t> verifier;
        const uint16_t* d = reinterpret_cast<const uint16_t*>(data);
        const size_t ds = size / 2;
        for(int i = 0; i < ds; i++) {
            verifier.append(d[i]);
        }
        if(ds * 2 != size) {
            verifier.append(*(data + size - 1));
        }
        verifier.append(htons(size));
        verifier.append(header->protocol);
        verifier.append(header->saddr >> 16);
        verifier.append(header->saddr & 0xFFFF);
        verifier.append(header->daddr >> 16);
        verifier.append(header->daddr % 0xFFFF);
        return verifier.verify();
    }
public:
    L4ChecksumParser(Parser* parent) : Parser(parent) {}
    virtual void process(const u_char* packet, size_t size) override {
        const iphdr* header = reinterpret_cast<const iphdr*>(packet);
        const uint16_t total = ntohs(header->tot_len);
        const size_t hlen = header->ihl * 4;
        if(size >= total && total >= hlen && verify(header, packet + hlen, total - hlen)) {
            count_++;
        }
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        metrics.push_back({29, "Correct L4 checksum", count_ });
    }
};

class TcpFlagsParser : public Parser {
    std::unordered_map<uint8_t, Parser*> flags_;
    Parser* other_;
public:
    TcpFlagsParser(Parser* parent) : Parser(parent), flags_{
        { TH_SYN, new CounterParser(20, "Tcp flags SYN", this) },
        { TH_SYN | TH_ACK, new CounterParser(21, "Tcp flags SYN + ACK", this) },
        { TH_ACK, new CounterParser(22, "Tcp flags ACK", this) },
        { TH_FIN | TH_ACK, new CounterParser(23, "Tcp flags FIN + ACK", this) },
        { TH_RST, new CounterParser(24, "Tcp flags RST", this) },
        { TH_RST | TH_ACK, new CounterParser(25, "Tcp flags RST + ACK", this) }
    }, other_(new CounterParser(26, "Tcp flags other", this)) {}
    virtual void process(const u_char* packet, size_t size) override {
        const tcphdr* header = reinterpret_cast<const tcphdr*>(packet);
        const auto fnd = flags_.find(header->th_flags);
        (fnd == flags_.cend() ? other_ : fnd->second)->process(packet, size);
    }
};

class TcpParser : public Parser {
    std::unordered_set<uint16_t> &src_, &dst_;
public:
    TcpParser(std::unordered_set<uint16_t>& src, std::unordered_set<uint16_t>& dst, Parser* parent) :
        Parser(parent), src_(src), dst_(dst) {
        new TcpFlagsParser(this);
        new CounterParser(10, "Protocol TCP", this);
    }
    virtual void process(const u_char* packet, size_t size) override {
        if(size >= sizeof(tcphdr)) {
            Parser::process(packet, size);
            const tcphdr* header = reinterpret_cast<const tcphdr*>(packet);
            src_.insert(header->source);
            dst_.insert(header->dest);
        }
    }
};

class UdpParser : public Parser {
    std::unordered_set<uint16_t> &src_, &dst_;
public:
    UdpParser(std::unordered_set<uint16_t>& src, std::unordered_set<uint16_t>& dst, Parser* parent) :
        Parser(parent), src_(src), dst_(dst) {
        new CounterParser(11, "Protocol UDP", this);
    }
    virtual void process(const u_char* packet, size_t size) override {
        if(size >= sizeof(udphdr)) {
            const udphdr* header = reinterpret_cast<const udphdr*>(packet);
            src_.insert(header->source);
            dst_.insert(header->dest);
        }
    }
};

class L4ProtocolParser : public Parser {
    std::unordered_set<uint16_t> src_, dst_;
    std::unordered_map<uint8_t, Parser*> protos_;
    Parser* other_;
public:
    L4ProtocolParser(Parser* parent) : Parser(parent), protos_{
        { IPPROTO_TCP, new TcpParser(src_, dst_, this) },
        { IPPROTO_UDP, new UdpParser(src_, dst_, this) },
        { IPPROTO_ICMP, new CounterParser(12, "Protocol ICMP", this) }
    }, other_(new CounterParser(13, "Protocol other L4", this)) {}
    virtual void process(const u_char* packet, size_t size) override {
        const iphdr* header = reinterpret_cast<const iphdr*>(packet);
        const size_t hlen = header->ihl * 4;
        if(size >= hlen) {
            const auto fnd = protos_.find(header->protocol);
            (fnd == protos_.cend() ? other_ : fnd->second)->process(packet + hlen, size - hlen);
        }
    }
    virtual void metrics(std::list<Metric>& metrics) const override {
        Parser::metrics(metrics);
        metrics.push_back({18, "Unique src port", src_.size() });
        metrics.push_back({19, "Unique dst port", dst_.size() });
    }
};

class IpParser : public Parser {
public:
    IpParser(Parser* parent) : Parser(parent) {
        new CounterParser(8, "Protocol IPv4", this);
        new IpAddressParser(this);
        new L3ChecksumParser(this);
        new L4ChecksumParser(this);
        new L4ProtocolParser(this);
    }
    void process(const u_char* packet, size_t size) override {
        if(size >= sizeof(iphdr)) {
            Parser::process(packet, size);
        }
    }
};

class L3ProtocolParser : public Parser {
    Parser *ip_, *other_;
public:
    L3ProtocolParser(Parser* parent) : Parser(parent),
        ip_(new IpParser(this)), other_(new CounterParser(9, "Protocol Non-IPv4", this)) {}
    virtual void process(const u_char* packet, size_t size) override {
        const uint16_t proto = ntohs(reinterpret_cast<const ethhdr*>(packet)->h_proto);
        (proto == ETH_P_IP ? ip_ : other_)->process(packet + sizeof(ethhdr), size - sizeof(ethhdr));
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