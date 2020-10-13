#include "Processor.h"
#include <iostream>
#include <filesystem>
using namespace packpars;

class PrintMetricsUtil {
	std::list<Metric> metrics_;
	size_t maxDescriptionSize() const {
		size_t mdesc;
		for(const Metric& metric : metrics_) {
			if(metric.description.size() > mdesc) {
				mdesc = metric.description.size();
			}
		}
		return mdesc;
	}
public:
	explicit PrintMetricsUtil(const std::list<Metric>& metrics) :
		metrics_(metrics) {
		metrics_.sort();
	}
	PrintMetricsUtil(const PrintMetricsUtil&) = delete;
	PrintMetricsUtil& operator=(const PrintMetricsUtil&) = delete;
	void print() const {
		size_t const mdesc = maxDescriptionSize();
		for(const Metric& metric : metrics_) {
			std::cout.width(mdesc);
			std::cout.setf(std::cout.flags() | std::ios::left);
			std::cout << metric.description << " : " << metric.value << std::endl;
		}
	}
};

int main(int argc, char* argv[]) {
	if(argc < 2) {
		std::cerr << "Usage: packpars <directory>";
		return 0;
	}
	try {
		for(const auto entry : std::filesystem::directory_iterator(argv[1])) {
			const std::filesystem::path path(entry);
			if(entry.is_regular_file() && path.extension() == ".pcap") {
				std::cout << "File " << path.filename() << std::endl;
				PrintMetricsUtil(Processor(path.native()).process()).print();
				std::cout << std::endl;
			}
		}
	}
	catch(const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return -1;
	}
	catch(...) {
		std::cerr << "Error: unknown" << std::endl;
		return -1;
	}
	return 0;
}
