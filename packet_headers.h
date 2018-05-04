#ifndef PACKET_HEADERS_H
#define PACKET_HEADERS_H
/* 网络层协议类型 */
#define IP_PROTOCOL       0x0800
#define ARP_PROTOCOL      0x0806

/* 传输层类型 */
#define ICMP_PROTOCOL       0x01
#define IGMP_PROTOCOL       0x02
#define TCP_PROTOCOL        0x06
#define UDP_PROTOCOL        0x11
#define IPv6_PROTOCOL       0x29

/*ARP协议opcode*/
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02

#include "packet_cat_arp.h"
#include "packet_cat_ethernet.h"
#include "packet_cat_ip.h"
#include "packet_cat_tcp.h"
#include "packet_cat_udp.h"
#include "packet_cat_icmp.h"
#include "packet_cat_http.h"
#endif // PACKET_HEADERS_H
