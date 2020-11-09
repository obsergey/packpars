#include "Processor.h"
#include <iostream>
#include <filesystem>
using namespace packpars;

size_t maxDescriptionSize(const std::list<Metric>& metrics) {
	size_t max = 0;
	for(const Metric& metric : metrics) {
		if(metric.description.size() > max) {
			max = metric.description.size();
		}
	}
	return max;
}

int main(int argc, char* argv[]) {
	if(argc < 2) {
		std::cerr << "Usage: packpars <pcap-filename>" << std::endl;
		return 0;
	}
	try {
		std::list<Metric> metrics = Processor(argv[1]).process();
		metrics.sort();
		const size_t descriptionSize = maxDescriptionSize(metrics);
		for(const Metric& metric : metrics) {
			std::cout.width(descriptionSize);
			std::cout.setf(std::cout.flags() | std::ios::left);
			std::cout << metric.description << " : " << metric.value << std::endl;
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
