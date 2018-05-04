#ifndef PACKET_TREE_H
#define PACKET_TREE_H
#include "packet_get.h"
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_tree:public QTreeWidget
{
        Q_OBJECT
public:
    packet_tree();
    void set_header(packet_get packet);

private:
    void set_Ethernet_header(packet_get packet);
    void set_ARP_header(packet_get packet);
    void set_IP_header(packet_get packet);
    void set_TCP_header(packet_get packet);
    void set_HTTP_header(packet_get packet);
    void set_UDP_header(packet_get packet);
    void set_ICMP_header(packet_get packet);

    QTreeWidgetItem * Ethernet_header;
    QTreeWidgetItem * ARP_header;
    QTreeWidgetItem * IP_header;

    QTreeWidgetItem * TCP_header;
    QTreeWidgetItem * UDP_header;
    QTreeWidgetItem * ICMP_header;
    QTreeWidgetItem * HTTP_header;
};

#endif // PACKET_TREE_H
