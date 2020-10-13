#include "Processor.h"
#include <iostream>
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
		PrintMetricsUtil(Processor(argv[1]).process()).print();
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
