#pragma once

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

void usage();
void get_myinfo(char* interface, Mac& mac, Ip& ip);
void get_smac(pcap_t* handle, Mac& smac, Ip& sip, Ip& myip, Mac& mymac);
void attack(pcap_t* handle, Mac& mymac, Ip& tip, Mac& smac, Ip& sip);
