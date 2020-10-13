#include "Processor.h"
#include "Parser.h"
#include <pcap.h>
#include <exception>

namespace packpars {

class PcapCallChecker {
public:
    PcapCallChecker() = delete;
    PcapCallChecker(const PcapCallChecker&) = delete;
    PcapCallChecker& operator=(const PcapCallChecker&) = delete;
    static pcap_t* open(std::string_view filename) {
        char errbuf[PCAP_ERRBUF_SIZE];
        if(auto pcap = pcap_open_offline(filename.data(), errbuf)) {
            return pcap;
        }
        throw std::runtime_error(errbuf);
    }
    static void loop(int error) {
        if(error != 0) {
            throw std::runtime_error("pcap loop error");
        }
    }
};

void processorCallback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    reinterpret_cast<Parser*>(args)->process(packet, pkthdr->len);
}

Processor::Processor(std::string_view filename) :
    pcap_(PcapCallChecker::open(filename)) {}

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
    PcapCallChecker::loop(pcap_loop(pcap_, -1, processorCallback, reinterpret_cast<u_char*>(common.get())));
    std::list<Metric> metrics;
    common->metrics(metrics);
    return metrics;
}

} // namespace packpars