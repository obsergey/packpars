#pragma once
#include "Metric.h"
#include <list>
typedef struct pcap pcap_t;

namespace packpars {

class Processor {
    pcap_t* pcap_;
public:
    explicit Processor(std::string_view filename);
    ~Processor();
    std::list<Metric> process();
};

} // namespace packpars