#ifndef PACKET_CAT_ICMP_H
#define PACKET_CAT_ICMP_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_cat_icmp
{
public:
    packet_cat_icmp(const u_char pkt_data[8]);
    u_char type;            //8位 类型
    u_char code;            //8位 代码
    u_short chksum;      //8位校验和
    u_short flag;       //标识符
    u_short seq;         //序列号 8位
    void print_header();
};

#endif // PACKET_CAT_ICMP_H
