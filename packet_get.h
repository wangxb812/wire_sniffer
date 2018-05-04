#ifndef PACKET_GET_H
#define PACKET_GET_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"
#include "packet_headers.h"
class packet_get
{
public:
    packet_get(int Num,struct pcap_pkthdr *header,const u_char * pkt_data);
    int Num;                     //包编号
    u_char * pkt_data;    //包的内容
    QString captured_time;      //截获时间
    bpf_u_int32 caplen;         //截获的包的长度
    bpf_u_int32 len;            //包本身应该的长度
    QString protocol;           //协议类型

    bool operator < (const packet_get &a) const {  return a.Num < Num;  }

    packet_cat_ethernet * ethernet_header;       //链路层报头

    //网络层报头
    packet_cat_arp * arp_header;                 //ARP报头
   packet_cat_ip * ip_header;                   //IP报头

    //传输层报头
    packet_cat_icmp * icmp_header;                               //ICMP报头
    //Packet_header_igmp * igmp_header;                               //ICMP报头
    packet_cat_udp * udp_header;                                 //UDP报头
    packet_cat_tcp * tcp_header;                 //TCP报头

    packet_cat_http * http;
    QString toQString();
    void print_packet();


private:
    void get_all_packet_header_and_protocol();
    void get_packet_ip_header();
    void get_packet_tcp_header();
    void get_packet_udp_header();
    void get_packet_icmp_header();
    void get_packet_igmp_header();
    void get_packet_http();

};

#endif // PACKET_GET_H
