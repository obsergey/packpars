#include "Processor.h"
#include "Parser.h"
#include <pcap.h>

namespace packpars {

void processorCallback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    reinterpret_cast<Parser*>(args)->process(packet, pkthdr->len);
}

Processor::Processor(std::string_view filename) :
    pcap_(pcap_open_offline(filename.data(), nullptr)) {}

Processor::~Processor() {
    try {
        pcap_close(pcap_);
    }
    catch(...) {
        // log exception in destructor here
    }
}

std::list<Metric> Processor::process() {
    std::unique_ptr<Parser> common = Parser::common();
    pcap_loop(pcap_, -1, processorCallback, reinterpret_cast<u_char*>(common.get()));
    std::list<Metric> metrics;
    common->metrics(metrics);
    return metrics;
}

} // namespace packpars