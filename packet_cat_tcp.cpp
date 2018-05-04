#include "packet_cat_tcp.h"

packet_cat_tcp::packet_cat_tcp(const u_char pkt_data[20])
{
    source_port=pkt_data[0];          //源端口地址  16位
        source_port=(source_port<<8)|pkt_data[1];

        destant_port=pkt_data[2];        //目的端口地址 16位
        destant_port=(destant_port<<8)|pkt_data[3];

        seq=pkt_data[4];//序列号32位
        seq=(seq<<8)|pkt_data[5];
        seq=(seq<<8)|pkt_data[6];
        seq=(seq<<8)|pkt_data[7];

        ack_seq=pkt_data[8];//确认序列号
        ack_seq=(ack_seq<<8)|pkt_data[9];
        ack_seq=(ack_seq<<8)|pkt_data[10];
        ack_seq=(ack_seq<<8)|pkt_data[11];

        head_len=pkt_data[12]>>4;
        doff=(pkt_data[12]<<4)>>4;
        doff=doff<<2|(pkt_data[13]>>6);

        urg=(pkt_data[13]<<2)>>7;
        ack=(pkt_data[13]<<3)>>7;
        psh=(pkt_data[13]<<4)>>7;
        rst=(pkt_data[13]<<5)>>7;
        syn=(pkt_data[13]<<6)>>7;
        fin=(pkt_data[13]<<7)>>7;

        window=pkt_data[14];                           //窗口大小 16位
        window=(window<<8)|pkt_data[15];
        check=pkt_data[16];                             //校验和 16位
        check=(check<<8)|pkt_data[17];
        urg_ptr=pkt_data[18];                           //紧急指针 16位
        urg_ptr=urg_ptr<<8|pkt_data[19];
}
void packet_cat_tcp::print_header()
{
    qDebug("source_port is :%.4x .",source_port);
    qDebug("destant_port is :%.4x .",destant_port);
    qDebug("seq is :%.8x .",seq);
    qDebug("ack_seq is :%.8x .",ack_seq);
    qDebug("head_len is :%.2x .",head_len);
    qDebug("doff is :%.3x .",doff);
    qDebug("urg is :%.1x .",urg);
    qDebug("ack is :%.1x .",ack);
    qDebug("psh is :%.1x .",psh);
    qDebug("rst is :%.1x .",rst);
    qDebug("syn is :%.1x .",syn);
    qDebug("fin is :%.1x .",fin);
    qDebug("window is :%.4x .",window);
    qDebug("check is :%.4x .",check);
    qDebug("urg_ptr is :%.4x .",urg_ptr);
}
