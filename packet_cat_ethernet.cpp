#include "packet_cat_ethernet.h"

packet_cat_ethernet::packet_cat_ethernet(const u_char * pkt_data)
{
    for(int i=0;i<6;i++)
    {
        destant_mac[i]=pkt_data[i];
    }
    for(int i=6;i<12;i++)
    {
        source_mac[i-6]=pkt_data[i];
    }
    protocol=pkt_data[12];
    protocol=protocol<<8|pkt_data[13];
}
void packet_cat_ethernet::print_header()
{
    qDebug("destant_mac is :%.2x %.2x %.2x %.2x %.2x %.2x ",destant_mac[0],destant_mac[1],destant_mac[2],destant_mac[3],destant_mac[4],destant_mac[5]);
    qDebug("source_mac is :%.2x %.2x %.2x %.2x %.2x %.2x ",source_mac[0],source_mac[1],source_mac[2],source_mac[3],source_mac[4],source_mac[5]);
    qDebug("type is : %.4x\n",protocol);
}
