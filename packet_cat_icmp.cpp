#include "packet_cat_icmp.h"

packet_cat_icmp::packet_cat_icmp(const u_char pkt_data[8])
{
    type=pkt_data[0];            //8位 类型
    code=pkt_data[1];            //8位 代码
    chksum=pkt_data[2];        //16位校验和
    chksum=(chksum<<8)|pkt_data[3];
    flag=pkt_data[4];          //标识符
    flag=(flag<<8)|pkt_data[5];
    seq=pkt_data[6];           //序列号 8位
    seq=(seq<<8)|pkt_data[7];
}
void packet_cat_icmp::print_header()
{
    qDebug("type is :%.2x .",type);
    qDebug("code is :%.2x .",code);
    qDebug("chksum is :%.4x .",chksum);
    qDebug("flag is :%.4x .",flag);
    qDebug("seq is :%.4x .",seq);
}
