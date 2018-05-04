#ifndef PACKET_CAT_ETHERNET_H
#define PACKET_CAT_ETHERNET_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_cat_ethernet
{
public:
    packet_cat_ethernet(const u_char * pkt_data);
     u_char destant_mac[6];
     u_char source_mac[6];
     u_short protocol;

     void print_header();
};

#endif // PACKET_CAT_ETHERNET_H
