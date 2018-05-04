#include "packet_cat_http.h"

packet_cat_http::packet_cat_http(QString pkt_data)
{
    flag=0;
    this->header=pkt_data;
    if(header.startsWith("GET")||header.startsWith("HEAD")||header.startsWith("OPTIONS")||
            header.startsWith("POST")||header.startsWith("PUT")||header.startsWith("DELETE")||
            header.startsWith("TRACE")||header.startsWith("CONNECT"))    flag=1;
    else if(header.startsWith("HTTP"))   flag=2;
    else flag=3;
}
