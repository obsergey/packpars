#include "Processor.h"
#include <iostream>
using namespace packpars;

int main(int argc, char* argv[]) {
	if(argc < 2) {
		std::cerr << "Usage: packpars <directory>";
		return 0;
	}
	try {
		std::list<Metric> metrics = Processor(argv[1]).process();
		metrics.sort();
		for(const Metric& metric : metrics) {
			std::cout << metric.description << ": " << metric.value << std::endl;
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
