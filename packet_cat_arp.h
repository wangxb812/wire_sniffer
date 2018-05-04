#ifndef PACKET_CAT_ARP_H
#define PACKET_CAT_ARP_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_cat_arp
{
public:
    packet_cat_arp(const u_char * pkt_data);
    u_short arp_hardware;                   //硬件类型
    u_short arp_protocol;                   //协议类型
    u_char arp_hardware_lenth;              //硬件地址长度
    u_char arp_protocol_lenth;              //协议地址长度
    u_short arp_op;                         //操作码，1为请求 2为回复
    u_char arp_source_hardware_address[6];  //发送方MAC
    u_char arp_source_ip[4];                //发送方IP
    u_char arp_destant_hardware_address[6]; //接收方MAC
    u_char arp_destant_ip[4];               //接收方IP

    void print_header();

};

#endif // PACKET_CAT_ARP_H
