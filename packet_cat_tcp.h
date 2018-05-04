#ifndef PACKET_CAT_TCP_H
#define PACKET_CAT_TCP_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_cat_tcp
{
public:
    packet_cat_tcp(const u_char pkt_data[20]);
    u_short source_port;          //源端口地址  16位
    u_short destant_port;          //目的端口地址 16位
    u_int seq=0;              //序列号 32位
    u_int ack_seq=0;          //确认序列号
    u_char head_len:4;
    u_char doff:6;
    u_char urg:1;
    u_char ack:1;
    u_char psh:1;
    u_char rst:1;
    u_char syn:1;
    u_char fin:1;

    u_short window=0;         //窗口大小 16位
    u_short check=0;          //校验和 16位
    u_short urg_ptr=0;        //紧急指针 16位
    u_int opt;              //选项
    void print_header();
};

#endif // PACKET_CAT_TCP_H
