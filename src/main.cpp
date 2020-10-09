#include <iostream>
#include <pcap.h>

int main(int argc, char* argv[]) {
	pcap_t* handler = pcap_open_offline(argv[1], nullptr);
	pcap_close(handler);
	return 0;
}
