#include "packet_get.h"

packet_get::packet_get(int Num,struct pcap_pkthdr *header,const u_char *pkt_data)
{
    this->Num=Num;
    this->captured_time=QString("%1").arg(ctime(&(header->ts.tv_sec)));
    this->caplen=header->caplen;
        this->len=header->len;
        this->pkt_data=new u_char[caplen+10];
        for(int i=0;i<caplen;i++) this->pkt_data[i]=pkt_data[i];
        get_all_packet_header_and_protocol();
}
void packet_get::get_all_packet_header_and_protocol()
{
    ethernet_header=new packet_cat_ethernet(pkt_data);
    //ethernet_header->print_header();
    if(ARP_PROTOCOL==ethernet_header->protocol)
    {
        protocol+="ARP/";
        arp_header=new packet_cat_arp(pkt_data);
    }
    else if(IP_PROTOCOL==ethernet_header->protocol)
    {
        protocol+="IP/";
        get_packet_ip_header();
    }
    else  protocol+="OTHER/";
    //qDebug()<<protocol;
}

void packet_get::get_packet_ip_header()
{
    ip_header=new packet_cat_ip(pkt_data);
    //ip_header->print_header();
    if(ip_header->protocol==TCP_PROTOCOL)
    {
        protocol+="TCP/";
        get_packet_tcp_header();
    }
    else if(ip_header->protocol==UDP_PROTOCOL)
    {
        protocol+="UDP/";
        get_packet_udp_header();
    }
    else if(ip_header->protocol==ICMP_PROTOCOL)
    {
        protocol+="ICMP/";
        get_packet_icmp_header();
    }
//    else if(ip_header->protocol==IGMP_PROTOCOL)
//    {
//        protocol+="IGMP/";
//        get_packet_igmp_header();
//    }
    else
    {
        protocol+="OTHER/";
    }
}

void packet_get::get_packet_tcp_header()
{
    u_char header[20];
    for(int i=0;i<20;i++)
    {
        if(ip_header->header_len==6) header[i]=pkt_data[i+14+24];
        else header[i]=pkt_data[i+14+20];
    }
    tcp_header=new packet_cat_tcp(header);
    //tcp_header->print_header();
    if(tcp_header->source_port==80||tcp_header->destant_port==80)
    {
        get_packet_http();
    }
}

void packet_get::get_packet_http()
{
    int len=caplen-14-20-20;
    char * header_char=new char[len+10];
    for(int i=0;i<len;i++)
    {
        header_char[i]=(char)pkt_data[i+14+40];
    }
    header_char[len+1]='\0';
    QString header_QString=QString("%1").arg(header_char);

    http=new packet_cat_http(header_QString);
    if(http->flag==1) this->protocol+="HTTP/Request";
    else if(http->flag==2) this->protocol+="HTTP/Response";
    else this->protocol+="HTTP/other";
}

void packet_get::get_packet_udp_header()
{
    u_char header[8];
    for(int i=0;i<8;i++)
    {
        if(ip_header->header_len==6) header[i]=pkt_data[i+14+24];
        else header[i]=pkt_data[i+14+20];
    }
    udp_header=new packet_cat_udp(header);
    //udp_header->print_header();

}

void packet_get::get_packet_icmp_header()
{
    u_char header[8];
    for(int i=0;i<8;i++)
    {
        if(ip_header->header_len==6) header[i]=pkt_data[i+14+24];
        else header[i]=pkt_data[i+14+20];
    }
    icmp_header=new packet_cat_icmp(header);
    //icmp_header->print_header();
}

void packet_get::get_packet_igmp_header()
{
//    u_char header[8];
//    for(int i=0;i<8;i++)
//    {
//        if(ip_header->header_len==6) header[i]=pkt_data[i+14+24];
//        else header[i]=pkt_data[i+14+20];
//    }
//    icmp_header=new Packet_header_igmp(header);
//    //icmp_header->print_header();
}

void packet_get::print_packet()
{
    /* print pkt timestamp and pkt len */
    // qDebug()<<; //将结构中的信息转换为真实世界的时间，以字符串的形式显示
    qDebug("%ld",len);
    /* Print the packet */
    for (int i=1; i < caplen + 1; i+=LINE_LEN)
    {
        qDebug("%.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x %.2x "
               ,pkt_data[i-1],pkt_data[i],pkt_data[i+1],pkt_data[i+2]
                ,pkt_data[i+3],pkt_data[i+4],pkt_data[i+5],pkt_data[i+6]
                ,pkt_data[i+7],pkt_data[i+8],pkt_data[i+9],pkt_data[i+10]
                ,pkt_data[i+11],pkt_data[i+12],pkt_data[i+13],pkt_data[i+14]);
    }
}

QString packet_get::toQString()
{
    QString show_string;
    for (int i=0; i<caplen; i+=LINE_LEN)
    {
        QString line;
        line+=QString("%1:").arg(i*10,4,16,QChar('0'))+"   ";
        line+=QString("%1 %2 %3 %4 %5 %6 %7 %8 %9 %10 %11 %12 %13 %14 %15 %16    ")
                .arg(pkt_data[i+0],2,16,QChar('0'))
                .arg(pkt_data[i+1],2,16,QChar('0'))
                .arg(pkt_data[i+2],2,16,QChar('0'))
                .arg(pkt_data[i+3],2,16,QChar('0'))
                .arg(pkt_data[i+4],2,16,QChar('0'))
                .arg(pkt_data[i+5],2,16,QChar('0'))
                .arg(pkt_data[i+6],2,16,QChar('0'))
                .arg(pkt_data[i+7],2,16,QChar('0'))
                .arg(pkt_data[i+8],2,16,QChar('0'))
                .arg(pkt_data[i+9],2,16,QChar('0'))
                .arg(pkt_data[i+10],2,16,QChar('0'))
                .arg(pkt_data[i+11],2,16,QChar('0'))
                .arg(pkt_data[i+12],2,16,QChar('0'))
                .arg(pkt_data[i+13],2,16,QChar('0'))
                .arg(pkt_data[i+14],2,16,QChar('0'))
                .arg(pkt_data[i+15],2,16,QChar('0'));

        for(int j=0;j<16;j++)
        {
            char temp[2];
            if(pkt_data[i+j]>=32&&pkt_data[i+j]<=126) temp[0]=(char)pkt_data[i+j];
            else temp[0]='.';
            temp[1]='\0';
            line+=QString("%1").arg(temp);
        }

        show_string+=line+"\n";
    }
    return show_string;
}
