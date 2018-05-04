#ifndef PACKET_CAT_IP_H
#define PACKET_CAT_IP_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_cat_ip
{
public:
    packet_cat_ip(const u_char * pkt_data);
    u_char version:4;       //版本
    u_char header_len:4;    //首部长度
    u_char tos;             //TOS 服务类型
    u_short total_len;      //包总长 u_short占两个字节
    u_short id;             //标识
    u_char flag;            //标志
    u_short offset:13;          //片偏移
    u_char ttl;             //生存时间
    u_char protocol;           //协议
    u_short check;          //校验和
    u_char source_ip[4];  //源地址
    u_char destant_ip[4]; //目的地址
    u_char op_pad[4];       //选项等
    void print_header();

};

#endif // PACKET_CAT_IP_H
