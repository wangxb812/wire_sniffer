#ifndef PACKET_CAT_UDP_H
#define PACKET_CAT_UDP_H

#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_cat_udp
{
public:
    packet_cat_udp(const u_char pkt_data[20]);
    u_short source_port;      //源端口  16位
    u_short destant_port;      //目的端口 16位
    u_short len;        //数据报长度 16位
    u_short check;      //校验和 16位
    void print_header();
};

#endif // PACKET_CAT_UDP_H
