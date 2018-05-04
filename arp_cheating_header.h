#ifndef ARP_CHEATING_HEADER_H
#define ARP_CHEATING_HEADER_H
#ifndef PCAP_CHEATING_HEADER_H
#define PCAP_CHEATING_HEADER_H

#include "public_header_for_wpcap.h"
#include "arp_cheating_header.h"
#include "public_qt.h"
#define MSLEEP_TIME 500

#define ARP_OP_ALL 1
#define ARP_OP_IP 2
#define ETHPROTOCAL_IPV4 0x0800 // 以太网上层协议类型: IPv4
#define ETHPROTOCAL_ARP	0x0806 // 以太网上层协议类型: ARP

#define HARD_ETHERNET 0x0001
#define ARP_REQUEST 0x0001 // ARP 请求
#define ARP_RESPONCE 0x0002 // ARP 应答

#define MAC_LEN 6		// MAC 地址, 128 bits = 6 bytes
#define IPV4_LEN 4		// IPV4 地址, 32 bits = 4 bytes
#define PADDING_LEN 18		// ARP 数据包的有效载荷长度

typedef struct enthernet{
    u_char d_mac[6];
    u_char s_mac[6];
    qint16 type;
}enthernet;

//arp
typedef struct arphdr
{
    u_short ar_hrd;
    u_short ar_pro;
    u_char ar_hln;
    u_char ar_pln;
    u_short ar_op;
}arp_header;

/*生成的ARP报头*/
typedef struct ether_arp
{
    arp_header ea_hdr;
    u_char arp_sha[6];
    u_char arp_spa[4];
    u_char arp_tha[6];
    u_char arp_tpa[4];
}eth_arp;

// ARP 包
typedef struct arp_packet {
    enthernet eh;				// 以太网首部
    ether_arp ah;					// ARP 首部
    u_char padding[PADDING_LEN];
} arp_packet;

#endif // PCAP_CHEATING_HEADER_H

#endif // ARP_CHEATING_HEADER_H
