#include "packet_cat_ip.h"
#include "qdebug.h"
packet_cat_ip::packet_cat_ip(const u_char *pkt_data)
{
    u_char header[24];
    qDebug()<<header;
    for(int i=0;i<24;i++)
    {
        header[i]=pkt_data[i+14];
    }
    version=header[0]>>4;
    header_len=(header[0]<<4)>>4;
    tos=header[1];

    total_len=header[2]<<8|header[3];

    id=(header[4]<<8)|header[5];

    flag=header[6]>>5;

    offset=(header[6]<<3)>>3;
    offset=offset<<8|header[7];

    ttl=header[8];
    protocol=header[9];

    check=header[10];
    check=check<<8|header[11];

    for(int i=0;i<4;i++)
    {
        source_ip[i]=header[i+12];//原地址
        destant_ip[i]=header[i+16];//目的地址
    }

    if(header_len==6)
    {
        for(int i=0;i<4;i++)
        {
            op_pad[4]=header[i+20];
        }
    }
}

void packet_cat_ip::print_header()
{
    qDebug("version is :%.2x .",version);
    qDebug("header_len is :%.2x .",header_len);
    qDebug("tos is :%.2x .",tos);
    qDebug("total_len is :%.4x .",total_len);
    qDebug("id is :%.4x .",id);
    qDebug("flag is :%.2x .",flag);
    qDebug("offset is :%.4x .",offset);
    qDebug("ttl is :%.2x .",ttl);
    qDebug("protocol is :%.2x .",protocol);
    qDebug("check is :%.4x .",check);
    qDebug("source_ip is :%.2x %.2x %.2x %.2x ",source_ip[0],source_ip[1],source_ip[2],source_ip[3]);
    qDebug("destant_ip is :%.2x %.2x %.2x %.2x ",destant_ip[0],destant_ip[1],destant_ip[2],destant_ip[3]);
    if(header_len==6)
    {
        qDebug("op_pad is :%.2x %.2x %.2x %.2x ",op_pad[0],op_pad[1],op_pad[2],op_pad[3]);
    }
    qDebug("\n");qDebug("\n");
}

