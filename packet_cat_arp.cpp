#include "packet_cat_arp.h"

packet_cat_arp::packet_cat_arp(const u_char * pkt_data)
{
    u_char header[1000];
    for(int i=0;i<28;i++)
    {
        header[i]=pkt_data[i+14];
    }
    arp_hardware=header[0];                     //硬件类型
    arp_hardware=arp_hardware<<8|header[1];
    arp_protocol=header[2];                     //协议类型
    arp_protocol=arp_protocol<<8|header[3];
    arp_hardware_lenth=header[4];               //硬件地址长度
    arp_protocol_lenth=header[5];               //协议地址长度
    arp_op=header[6];                           //操作码，1为请求 2为回复
    arp_op=arp_op<<8|header[7];
    for(int i=0;i<6;i++)
    {
        arp_source_hardware_address[i]=header[i+8];               //发送方MAC
        arp_destant_hardware_address[i]=header[i+18];              //接收方MAC
    }
    for(int i=0;i<4;i++)
    {
        arp_source_ip[i]=header[i+14];                //发送方IP
        arp_destant_ip[i]=header[i+24];               //接收方IP
    }
}
void packet_cat_arp::print_header()
{
    qDebug("arp_hardware is :%.4x .",arp_hardware);
       qDebug("arp_protocol is :%.4x .",arp_protocol);
       qDebug("arp_hardware_lenth is :%.2x .",arp_hardware_lenth);
       qDebug("arp_protocol_lenth is :%.2x .",arp_protocol_lenth);
       qDebug("arp_op is :%.4x .",arp_op);
       qDebug("arp_source_ip is :%.2x %.2x %.2x %.2x ",arp_source_ip[0],arp_source_ip[1],arp_source_ip[2],arp_source_ip[3]);
       qDebug("arp_destant_ip is :%.2x %.2x %.2x %.2x ",arp_destant_ip[0],arp_destant_ip[1],arp_destant_ip[2],arp_destant_ip[3]);
       qDebug("arp_source_mac is :%.2x %.2x %.2x %.2x %.2x %.2x ",arp_source_hardware_address[0],arp_source_hardware_address[1],arp_source_hardware_address[2]
               ,arp_source_hardware_address[3],arp_source_hardware_address[4],arp_source_hardware_address[5]);
       qDebug("arp_destant_mac is :%.2x %.2x %.2x %.2x %.2x %.2x \n",arp_destant_hardware_address[0],arp_destant_hardware_address[1],arp_destant_hardware_address[2]
               ,arp_destant_hardware_address[3],arp_destant_hardware_address[4],arp_destant_hardware_address[5]);
}
