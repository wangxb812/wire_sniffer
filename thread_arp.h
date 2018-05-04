#ifndef THREAD_ARP_H
#define THREAD_ARP_H

#include "public_header_for_wpcap.h"
#include "public_qt.h"
#include "arp_cheating_header.h"
#define OID_802_3_CURRENT_ADDRESS 0x01010102
class thread_arp:public QThread
{
public:
    thread_arp();
    void init(pcap_if_t *d, pcap_if_t *inalldevs,char *ip,int inop=ARP_OP_ALL,char *dip=0);

   private:

       int op;
       char ipaddr[32];
       char dipaddr[32];

       pcap_if_t *dev_if_t,*alldevs;
       virtual void run();

       BOOLEAN GetSelfMac(
           _In_ PCHAR AdapterName,
           _Out_ PUCHAR MacAddr);

       void make_arp_packet(u_char* packet, u_char* src_mac, u_int src_ip, u_int dst_ip, quint16 op);

       inline unsigned short htons(unsigned short in){
           char * x =(char *)&in;
           char y[2];
           y[1]=x[0];
           y[0]=x[1];
           return *(unsigned short *)y;
       }
       inline static quint32 htonl(quint32 in){
           char * x =(char *)&in;
           char y[4];
           y[0]=x[3];
           y[1]=x[2];
           y[2]=x[1];
           y[3]=x[0];
           return *(quint32 *)y;
       }
       inline static quint32 inet_addr(const char *cp){
           quint32 temp;
           char * c= (char *)&temp;
           sscanf(cp,"%d.%d.%d.%d",&c[0],&c[1],&c[2],&c[3]);
           return temp;
       }

};

#endif // THREAD_ARP_H
