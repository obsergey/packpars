#include "Processor.h"
#include <iostream>
using namespace packpars;

int main(int argc, char* argv[]) {
	if(argc > 1) {
		std::list<Metric> metrics = Processor(argv[1]).process();
		metrics.sort();
		for(const Metric& metric : metrics) {
			std::cout << metric.description << ": " << metric.value << std::endl;
		}
	}
	return 0;
}
