#include "packet_tree.h"

packet_tree::packet_tree():QTreeWidget(Q_NULLPTR)
{

}
void packet_tree::set_header(packet_get packet)
{
    set_Ethernet_header(packet);
    this->setHeaderHidden(true);
    this->expandAll();
}
void packet_tree::set_Ethernet_header(packet_get packet)
{
    Ethernet_header = new QTreeWidgetItem(this,QStringList(QString("以太网协议")));

    QTreeWidgetItem * Ethernet_header_source_mac;
    QTreeWidgetItem * Ethernet_header_distant_mac;
    QTreeWidgetItem * Ethernet_header_protocol;

    Ethernet_header_source_mac =
            new QTreeWidgetItem(Ethernet_header,QStringList(QString("源头地址:(%1:%2:%3:%4:%5:%6)")
                                                            .arg(packet.ethernet_header->source_mac[0],2,16,QChar('0'))
                                .arg(packet.ethernet_header->source_mac[1],2,16,QChar('0'))
            .arg(packet.ethernet_header->source_mac[2],2,16,QChar('0'))
            .arg(packet.ethernet_header->source_mac[3],2,16,QChar('0'))
            .arg(packet.ethernet_header->source_mac[4],2,16,QChar('0'))
            .arg(packet.ethernet_header->source_mac[5],2,16,QChar('0')))); //源MAC地址

    Ethernet_header_distant_mac =
            new QTreeWidgetItem(Ethernet_header,QStringList(QString("目的地址:(%1:%2:%3:%4:%5:%6)")
                                                            .arg(packet.ethernet_header->destant_mac[0],2,16,QChar('0'))
                                .arg(packet.ethernet_header->destant_mac[1],2,16,QChar('0'))
            .arg(packet.ethernet_header->destant_mac[2],2,16,QChar('0'))
            .arg(packet.ethernet_header->destant_mac[3],2,16,QChar('0'))
            .arg(packet.ethernet_header->destant_mac[4],2,16,QChar('0'))
            .arg(packet.ethernet_header->destant_mac[5],2,16,QChar('0'))));//目的MAC地址


    if(ARP_PROTOCOL==packet.ethernet_header->protocol)
    {
        Ethernet_header_protocol = new QTreeWidgetItem(Ethernet_header,QStringList(QString("协议类型:0x%1(ARP)").arg(packet.ethernet_header->protocol,4,16,QChar('0')))); //协议
        set_ARP_header(packet);
    }
    else if(IP_PROTOCOL==packet.ethernet_header->protocol)
    {
        Ethernet_header_protocol = new QTreeWidgetItem(Ethernet_header,QStringList(QString("协议类型:0x%1(IP)").arg(packet.ethernet_header->protocol,4,16,QChar('0')))); //协议
        set_IP_header(packet);
    }
    else
    {
        Ethernet_header_protocol = new QTreeWidgetItem(Ethernet_header,QStringList(QString("协议类型:0x%1(其他)").arg(packet.ethernet_header->protocol,4,16,QChar('0')))); //协议
        QTreeWidgetItem * other_header = new QTreeWidgetItem(this,QStringList(QString("Other Protocol")));
    }
    //添加子节点
    Ethernet_header->addChild(Ethernet_header_source_mac);
    Ethernet_header->addChild(Ethernet_header_distant_mac);
    Ethernet_header->addChild(Ethernet_header_protocol);

}
void packet_tree::set_ARP_header(packet_get packet)
{
    ARP_header = new QTreeWidgetItem(this,QStringList(QString("Address Resolution Protocol")));
    QTreeWidgetItem * ARP_header_arp_hardware;
    QTreeWidgetItem * ARP_header_arp_protocol;
    QTreeWidgetItem * ARP_header_arp_hardware_lenth;
    QTreeWidgetItem * ARP_header_arp_protocol_lenth;
    QTreeWidgetItem * ARP_header_arp_op;
    QTreeWidgetItem * ARP_header_arp_source_hardware_address;
    QTreeWidgetItem * ARP_header_arp_source_ip;
    QTreeWidgetItem * ARP_header_arp_destant_hardware_address;
    QTreeWidgetItem * ARP_header_arp_destant_ip;

    ARP_header_arp_hardware
            = new QTreeWidgetItem(ARP_header,QStringList(QString("arp_hardware :0x%1(Ethernet Protocol)")
                                                         .arg(packet.arp_header->arp_hardware,4,16,QChar('0'))));

    ARP_header_arp_protocol
            =new QTreeWidgetItem(ARP_header,QStringList(QString("arp_protocol :0x%1(Internet Protocol)")
                                                        .arg(packet.arp_header->arp_protocol,4,16,QChar('0'))));

    ARP_header_arp_hardware_lenth
            = new QTreeWidgetItem(ARP_header,QStringList(QString("arp_hardware_lenth :0x%1")
                                                         .arg(packet.arp_header->arp_hardware_lenth,2,16,QChar('0'))));
    ARP_header_arp_protocol_lenth
            =new QTreeWidgetItem(ARP_header,QStringList(QString("arp_protocol_lenth :0x%1")
                                                        .arg(packet.arp_header->arp_protocol_lenth,2,16,QChar('0'))));
    if(packet.arp_header->arp_op==ARP_REQUEST)
        ARP_header_arp_op
                = new QTreeWidgetItem(ARP_header,QStringList(QString("arp_Opcode :0x%1(request)")
                                                             .arg(packet.arp_header->arp_op,4,16,QChar('0'))));
    if(packet.arp_header->arp_op==ARP_REPLY)
        ARP_header_arp_op
                = new QTreeWidgetItem(ARP_header,QStringList(QString("arp_Opcode :0x%1(reply)")
                                                             .arg(packet.arp_header->arp_op,4,16,QChar('0'))));

    ARP_header_arp_source_hardware_address
            =new QTreeWidgetItem(ARP_header,QStringList(QString("arp_source_hardware_address :(%1:%2:%3:%4:%5:%6)")
                                                        .arg(packet.arp_header->arp_source_hardware_address[0],2,16,QChar('0'))
                                 .arg(packet.arp_header->arp_source_hardware_address[1],2,16,QChar('0'))
            .arg(packet.arp_header->arp_source_hardware_address[2],2,16,QChar('0'))
            .arg(packet.arp_header->arp_source_hardware_address[3],2,16,QChar('0'))
            .arg(packet.arp_header->arp_source_hardware_address[4],2,16,QChar('0'))
            .arg(packet.arp_header->arp_source_hardware_address[5],2,16,QChar('0'))));

    ARP_header_arp_destant_hardware_address
            =new QTreeWidgetItem(ARP_header,QStringList(QString("arp_destant_hardware_address :(%1:%2:%3:%4:%5:%6)")
                                                        .arg(packet.arp_header->arp_destant_hardware_address[0],2,16,QChar('0'))
                                 .arg(packet.arp_header->arp_destant_hardware_address[1],2,16,QChar('0'))
            .arg(packet.arp_header->arp_destant_hardware_address[2],2,16,QChar('0'))
            .arg(packet.arp_header->arp_destant_hardware_address[3],2,16,QChar('0'))
            .arg(packet.arp_header->arp_destant_hardware_address[4],2,16,QChar('0'))
            .arg(packet.arp_header->arp_destant_hardware_address[5],2,16,QChar('0'))));

    ARP_header_arp_source_ip
            =new QTreeWidgetItem(ARP_header,QStringList(QString("arp_source_ip :(%1.%2.%3.%4)")
                                                        .arg(packet.arp_header->arp_source_ip[0],1,10)
                                 .arg(packet.arp_header->arp_source_ip[1],1,10)
            .arg(packet.arp_header->arp_source_ip[2],1,10)
            .arg(packet.arp_header->arp_source_ip[3],1,10)));

    ARP_header_arp_destant_ip
            =new QTreeWidgetItem(ARP_header,QStringList(QString("arp_destant_ip :(%1.%2.%3.%4)")
                                                        .arg(packet.arp_header->arp_destant_ip[0],1,10)
                                 .arg(packet.arp_header->arp_destant_ip[1],1,10)
            .arg(packet.arp_header->arp_destant_ip[2],1,10)
            .arg(packet.arp_header->arp_destant_ip[3],1,10)));


    ARP_header->addChild(ARP_header_arp_hardware);
    ARP_header->addChild(ARP_header_arp_protocol);
    ARP_header->addChild(ARP_header_arp_hardware_lenth);
    ARP_header->addChild(ARP_header_arp_protocol_lenth);
    ARP_header->addChild(ARP_header_arp_op);
    ARP_header->addChild(ARP_header_arp_source_hardware_address);
    ARP_header->addChild(ARP_header_arp_destant_hardware_address);
    ARP_header->addChild(ARP_header_arp_source_ip);
    ARP_header->addChild(ARP_header_arp_destant_ip);
    //    ARP_header->addChild(ARP_text);
    //    ARP_header->addChild(ARP_CRC);
}

void packet_tree::set_IP_header(packet_get packet)
{
    IP_header = new QTreeWidgetItem(this,QStringList(QString("Internet Protocol")));
    QTreeWidgetItem * IP_header_version;
    QTreeWidgetItem * IP_header_header_len;
    QTreeWidgetItem * IP_header_tos;
    QTreeWidgetItem * IP_header_total_len;
    QTreeWidgetItem * IP_header_id;
    QTreeWidgetItem * IP_header_flag;
    QTreeWidgetItem * IP_header_offset;
    QTreeWidgetItem * IP_header_ttl;
    QTreeWidgetItem * IP_header_protocol;
    QTreeWidgetItem * IP_header_check;
    QTreeWidgetItem * IP_header_source_ip;
    QTreeWidgetItem * IP_header_destant_ip;
    IP_header_version
            = new QTreeWidgetItem(IP_header,QStringList(QString("version :  %1")
                                                       .arg(packet.ip_header->version,1,10)));
    IP_header_header_len
            =new QTreeWidgetItem(IP_header,QStringList(QString("header_len :  %1")
                                                       .arg(packet.ip_header->header_len,2,10)));
    IP_header_tos
            = new QTreeWidgetItem(IP_header,QStringList(QString("tos :  %1")
                                                        .arg(packet.ip_header->tos,2,10)));
    IP_header_total_len
            = new QTreeWidgetItem(IP_header,QStringList(QString("total_len :  %1")
                                                        .arg(packet.ip_header->total_len,2,10)));
    IP_header_id
            = new QTreeWidgetItem(IP_header,QStringList(QString("id :  %1")
                                                        .arg(packet.ip_header->id,2,10)));
    IP_header_flag
            = new QTreeWidgetItem(IP_header,QStringList(QString("flag :  %1")
                                                        .arg(packet.ip_header->flag,2,10)));
    IP_header_offset
            = new QTreeWidgetItem(IP_header,QStringList(QString("offset :  %1")
                                                        .arg(packet.ip_header->offset,2,10)));
    IP_header_ttl
            = new QTreeWidgetItem(IP_header,QStringList(QString("ttl :  %1")
                                                        .arg(packet.ip_header->ttl,2,10)));

    if(packet.ip_header->protocol==TCP_PROTOCOL)
    {
        IP_header_protocol
                = new QTreeWidgetItem(IP_header,QStringList(QString("protocol :  0x%1(TCP)")
                                                            .arg(packet.ip_header->protocol,4,16,QChar('0'))));
        set_TCP_header(packet);
    }

    else if(packet.ip_header->protocol==UDP_PROTOCOL)
    {
        IP_header_protocol
                = new QTreeWidgetItem(IP_header,QStringList(QString("protocol :  0x%1(UDP)")
                                                            .arg(packet.ip_header->protocol,4,16,QChar('0'))));
        set_UDP_header(packet);
    }
    else if(packet.ip_header->protocol==ICMP_PROTOCOL)
    {
        IP_header_protocol
                = new QTreeWidgetItem(IP_header,QStringList(QString("protocol :  0x%1(ICMP)")
                                                            .arg(packet.ip_header->protocol,4,16,QChar('0'))));
        set_ICMP_header(packet);
    }
    else
    {
        IP_header_protocol
                = new QTreeWidgetItem(IP_header,QStringList(QString("protocol :  0x%1(OTHER)")
                                                            .arg(packet.ip_header->protocol,4,16,QChar('0'))));
        QTreeWidgetItem * other_header=new QTreeWidgetItem(this,QStringList(QString("OTHER Protocol")));
    }
    IP_header_check
            = new QTreeWidgetItem(IP_header,QStringList(QString("check :  0x%1")
                                                        .arg(packet.ip_header->check,4,16,QChar('0'))));

    IP_header_source_ip = new QTreeWidgetItem(IP_header,QStringList(QString("source_ip :(%1.%2.%3.%4)")
                                                                    .arg(packet.ip_header->source_ip[0],1,10)
                                              .arg(packet.ip_header->source_ip[1],1,10)
            .arg(packet.ip_header->source_ip[2],1,10)
            .arg(packet.ip_header->source_ip[3],1,10)));

    IP_header_destant_ip = new QTreeWidgetItem(IP_header,QStringList(QString("destation :(%1.%2.%3.%4)")
                                                                     .arg(packet.ip_header->destant_ip[0],1,10)
                                               .arg(packet.ip_header->destant_ip[1],1,10)
            .arg(packet.ip_header->destant_ip[2],1,10)
            .arg(packet.ip_header->destant_ip[3],1,10)));


    IP_header->addChild(IP_header_version);
    IP_header->addChild(IP_header_header_len);
    IP_header->addChild(IP_header_tos);
    IP_header->addChild(IP_header_total_len);
    IP_header->addChild(IP_header_id);
    IP_header->addChild(IP_header_flag);
    IP_header->addChild(IP_header_offset);
    IP_header->addChild(IP_header_ttl);
    IP_header->addChild(IP_header_protocol);
    IP_header->addChild(IP_header_check);
    IP_header->addChild(IP_header_source_ip);
    IP_header->addChild(IP_header_destant_ip);

}

void packet_tree::set_TCP_header(packet_get packet)
{
    TCP_header=new QTreeWidgetItem(this,QStringList(QString("Transport Control Protocol")));
    QTreeWidgetItem * TCP_header_source_port;
    QTreeWidgetItem * TCP_header_destant_port;
    QTreeWidgetItem * TCP_header_seq;
    QTreeWidgetItem * TCP_header_ack_seq;
    QTreeWidgetItem * TCP_header_head_len;
    QTreeWidgetItem * TCP_header_doff;

    QTreeWidgetItem * TCP_header_bits;
    QTreeWidgetItem * TCP_header_urg;
    QTreeWidgetItem * TCP_header_ack;
    QTreeWidgetItem * TCP_header_psh;
    QTreeWidgetItem * TCP_header_rst;
    QTreeWidgetItem * TCP_header_syn;
    QTreeWidgetItem * TCP_header_fin;

    QTreeWidgetItem * TCP_header_window;
    QTreeWidgetItem * TCP_header_check;
    QTreeWidgetItem * TCP_header_urg_ptr;
    QTreeWidgetItem * TCP_header_opt;


    TCP_header_source_port
            = new QTreeWidgetItem(TCP_header,QStringList(QString("source_port :  %1")
                                                         .arg(packet.tcp_header->source_port,1,10)));
    TCP_header_destant_port
            =new QTreeWidgetItem(TCP_header,QStringList(QString("destant_port :  %1")
                                                        .arg(packet.tcp_header->destant_port,1,10)));

    TCP_header_seq
            = new QTreeWidgetItem(TCP_header,QStringList(QString("seq :  0x%1")
                                                         .arg(packet.tcp_header->seq,8,16,QChar('0'))));

    TCP_header_ack_seq
            = new QTreeWidgetItem(TCP_header,QStringList(QString("ack_seq :  0x%1")
                                                         .arg(packet.tcp_header->ack_seq,8,16,QChar('0'))));

    TCP_header_head_len
            = new QTreeWidgetItem(IP_header,QStringList(QString("head_len :  %1")
                                                        .arg(packet.tcp_header->head_len,1,10)));

    TCP_header_doff
            = new QTreeWidgetItem(TCP_header,QStringList(QString("doff :  %1")
                                                         .arg(packet.tcp_header->doff,2,10)));

    TCP_header_bits
            = new QTreeWidgetItem(TCP_header,QStringList(QString("flags")));

    TCP_header_urg
            = new QTreeWidgetItem(TCP_header_bits,QStringList(QString("urg: %1")
                                                              .arg(packet.tcp_header->urg,1,10)));
    TCP_header_ack
            = new QTreeWidgetItem(TCP_header_bits,QStringList(QString("ack: %1")
                                                              .arg(packet.tcp_header->ack,1,10)));
    TCP_header_psh
            = new QTreeWidgetItem(TCP_header_bits,QStringList(QString("psh: %1")
                                                              .arg(packet.tcp_header->psh,1,10)));
    TCP_header_rst
            = new QTreeWidgetItem(TCP_header_bits,QStringList(QString("rst: %1")
                                                              .arg(packet.tcp_header->rst,1,10)));
    TCP_header_syn
            = new QTreeWidgetItem(TCP_header_bits,QStringList(QString("syn: %1")
                                                              .arg(packet.tcp_header->syn,1,10)));
    TCP_header_fin
            = new QTreeWidgetItem(TCP_header_bits,QStringList(QString("fin: %1")
                                                              .arg(packet.tcp_header->fin,1,10)));
    TCP_header_window
            = new QTreeWidgetItem(TCP_header,QStringList(QString("window :  %1")
                                                         .arg(packet.tcp_header->window,1,10)));
    TCP_header_check
            = new QTreeWidgetItem(TCP_header,QStringList(QString("check :  %1")
                                                         .arg(packet.tcp_header->check,1,10)));
    TCP_header_urg_ptr
            = new QTreeWidgetItem(TCP_header,QStringList(QString("urg_ptr :  %1")
                                                         .arg(packet.tcp_header->urg_ptr,1,10)));
    TCP_header_opt
            = new QTreeWidgetItem(TCP_header,QStringList(QString("opt :  0x%1")
                                                         .arg(packet.tcp_header->opt,1,16)));

    TCP_header->addChild(TCP_header_source_port);
    TCP_header->addChild(TCP_header_destant_port);
    TCP_header->addChild(TCP_header_seq);
    TCP_header->addChild(TCP_header_ack_seq);
    TCP_header->addChild(TCP_header_head_len);
    TCP_header->addChild(TCP_header_doff);
    TCP_header->addChild(TCP_header_bits);
    TCP_header_bits->addChild(TCP_header_urg);
    TCP_header_bits->addChild(TCP_header_ack);
    TCP_header_bits->addChild(TCP_header_psh);
    TCP_header_bits->addChild(TCP_header_rst);
    TCP_header_bits->addChild(TCP_header_syn);
    TCP_header_bits->addChild(TCP_header_fin);
    TCP_header->addChild(TCP_header_window);
    TCP_header->addChild(TCP_header_check);
    TCP_header->addChild(TCP_header_urg_ptr);
    TCP_header->addChild(TCP_header_opt);

    if(packet.tcp_header->source_port==80||packet.tcp_header->destant_port==80) set_HTTP_header(packet);
}

void packet_tree::set_HTTP_header(packet_get packet)
{
    HTTP_header=new QTreeWidgetItem(this,QStringList(QString("HyperText Transfer Protocol")));
    if(packet.http->flag==0||packet.http->flag==3)
    {
        QTreeWidgetItem * other_HTTP_headers
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("other http packet!")));
        HTTP_header->addChild(other_HTTP_headers);
    }
    if(packet.http->flag==1)
    {
        QTreeWidgetItem * HTTP_header_kind;
        QTreeWidgetItem * HTTP_header_method;
        QTreeWidgetItem * HTTP_header_URL;
        QTreeWidgetItem * HTTP_header_version;

        HTTP_header_kind
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("kind: Request")));
        HTTP_header_method
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("method: ")+packet.http->header.section("\r\n",0,0).section(" ",0,0)));
        HTTP_header_URL
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("URL: ")+packet.http->header.section("\r\n",0,0).section(" ",1,1)));
        HTTP_header_version
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("version: ")+packet.http->header.section("\r\n",0,0).section(" ",2,2)));

        HTTP_header->addChild(HTTP_header_kind);
        HTTP_header->addChild(HTTP_header_method);
        HTTP_header->addChild(HTTP_header_URL);
        HTTP_header->addChild(HTTP_header_version);
    }
    if(packet.http->flag==2)
    {
        QTreeWidgetItem * HTTP_header_kind;
        QTreeWidgetItem * HTTP_header_version;
        QTreeWidgetItem * HTTP_header_code;
        QTreeWidgetItem * HTTP_header_code_discribetion;

        HTTP_header_kind
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("kind: Response")));
        HTTP_header_version
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("version: ")+packet.http->header.section("\r\n",0,0).section(" ",0,0)));
        HTTP_header_code
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("code: ")+packet.http->header.section("\r\n",0,0).section(" ",1,1)));
        HTTP_header_code_discribetion
                = new QTreeWidgetItem(HTTP_header,QStringList(QString("code_discribetion: ")+packet.http->header.section("\r\n",0,0).section(" ",2,2)));

        HTTP_header->addChild(HTTP_header_kind);
        HTTP_header->addChild(HTTP_header_version);
        HTTP_header->addChild(HTTP_header_code);
        HTTP_header->addChild(HTTP_header_code_discribetion);
    }
}

void packet_tree::set_UDP_header(packet_get packet)
{
    UDP_header=new QTreeWidgetItem(this,QStringList(QString("User Datagram Protocol")));
    QTreeWidgetItem * UDP_header_source_port;//源端口  16位
    QTreeWidgetItem * UDP_header_destant_port;//目的端口 16位
    QTreeWidgetItem * UDP_header_len; //数据报长度 16位
    QTreeWidgetItem * UDP_header_check;//校验和 16位

    UDP_header_source_port
            = new QTreeWidgetItem(UDP_header,QStringList(QString("source_port :  %1")
                                                         .arg(packet.udp_header->source_port,1,10)));
    UDP_header_destant_port
            =new QTreeWidgetItem(UDP_header,QStringList(QString("destant_port :  %1")
                                                        .arg(packet.udp_header->destant_port,1,10)));

    UDP_header_len
            = new QTreeWidgetItem(UDP_header,QStringList(QString("seq :  0x%1")
                                                         .arg(packet.udp_header->len,1,10)));

    UDP_header_check
            = new QTreeWidgetItem(UDP_header,QStringList(QString("ack_seq :  %1")
                                                         .arg(packet.udp_header->check,1,10)));

    UDP_header->addChild(UDP_header_source_port);//源端口  16位
    UDP_header->addChild(UDP_header_destant_port);//目的端口 16位
    UDP_header->addChild(UDP_header_len); //数据报长度 16位
    UDP_header->addChild(UDP_header_check);//校验和 16位

}

void packet_tree::set_ICMP_header(packet_get packet)
{
    ICMP_header=new QTreeWidgetItem(this,QStringList(QString("Internet Control Message Protocol")));
    QTreeWidgetItem * ICMP_header_type;                //8位 类型
    QTreeWidgetItem * ICMP_header_code;                //8位 代码
    QTreeWidgetItem * ICMP_header_chksum;         //8位校验和
    QTreeWidgetItem * ICMP_header_flag;            //标识符
    QTreeWidgetItem * ICMP_header_seq;               //序列号 8位

    ICMP_header_type
            = new QTreeWidgetItem(ICMP_header,QStringList(QString("type :  %1")
                                                          .arg(packet.icmp_header->type,1,10)));
    ICMP_header_code
            =new QTreeWidgetItem(ICMP_header,QStringList(QString("code :  %1")
                                                         .arg(packet.icmp_header->code,1,10)));

    ICMP_header_chksum
            = new QTreeWidgetItem(ICMP_header,QStringList(QString("chksum :  0x%1")
                                                          .arg(packet.icmp_header->chksum,1,16)));

    ICMP_header_flag
            = new QTreeWidgetItem(ICMP_header,QStringList(QString("flag :  %1")
                                                          .arg(packet.icmp_header->flag,1,10)));
    ICMP_header_seq
            = new QTreeWidgetItem(ICMP_header,QStringList(QString("seq :  %1")
                                                          .arg(packet.icmp_header->seq,1,10)));
    ICMP_header->addChild(ICMP_header_type);
    ICMP_header->addChild(ICMP_header_code);
    ICMP_header->addChild(ICMP_header_chksum);
    ICMP_header->addChild(ICMP_header_flag);
    ICMP_header->addChild(ICMP_header_seq);
}
