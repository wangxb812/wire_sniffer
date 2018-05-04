#ifndef PACKET_TABLE_H
#define PACKET_TABLE_H
#include "packet_get.h"
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_table:public QTableWidget
{
        Q_OBJECT
public:
    packet_table();
    int row=0;

 public slots:
     void On_itemDoubleClicked(QTableWidgetItem * Item);

     void refresh_list(packet_get new_packet);
 signals:
    void clicked(int clicked_No);
};

#endif // PACKET_TABLE_H
