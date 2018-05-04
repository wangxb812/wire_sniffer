#ifndef PACKET_CAT_HTTP_H
#define PACKET_CAT_HTTP_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_cat_http
{
public:
    packet_cat_http(QString pkt_data);
    QString header;
    int flag;//是几就表示第几类头部
};

#endif // PACKET_CAT_HTTP_H
