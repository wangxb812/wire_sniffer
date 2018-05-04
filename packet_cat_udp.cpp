#include "packet_cat_udp.h"

packet_cat_udp::packet_cat_udp(const u_char pkt_data[20])
{
    source_port=pkt_data[0];          //源端口地址  16位
    source_port=(source_port<<8)|pkt_data[1];

    destant_port=pkt_data[2];        //目的端口地址 16位
    destant_port=(destant_port<<8)|pkt_data[3];


    len=pkt_data[4];          //源端口地址  16位
    len=(len<<8)|pkt_data[5];

    check=pkt_data[6];          //源端口地址  16位
    check=(check<<8)|pkt_data[7];
}
void packet_cat_udp::print_header()
{
    qDebug("source_port is :%.4x .",source_port);
    qDebug("destant_port is :%.4x .",destant_port);
    qDebug("len is :%.4x .",len);
    qDebug("check is :%.4x .",check);
}
