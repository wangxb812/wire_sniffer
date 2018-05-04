#include "packet_table.h"

packet_table::packet_table():QTableWidget(1,9,Q_NULLPTR)
{
    QStringList header;
    header<<"编号"<<"捕获时间"<<"捕获长度"<<"应有长度"<<"源MAC地址"<<"目的MAC地址"<<"协议类型"<<"源IP地址"<<"目的IP地址";
    this->setHorizontalHeaderLabels(header);

    connect(this,SIGNAL(itemDoubleClicked(QTableWidgetItem*)),this,SLOT(On_itemDoubleClicked(QTableWidgetItem*)));
    this->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    this->verticalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    this->horizontalHeader()->setSortIndicatorShown(true);
    connect(this->horizontalHeader(),SIGNAL(sectionClicked(int)),
            this,SLOT(sortByColumn(int)));
}

void packet_table::On_itemDoubleClicked(QTableWidgetItem *Item)
{
    int No=this->item(Item->row(),0)->text().toInt(nullptr,10);
    emit clicked(No);
}

void packet_table::refresh_list(packet_get new_packet)
{
    if(!new_packet.protocol.isEmpty())
    {
        bool ok;
        this->setRowCount(row+1);

        QVariant function_num=new_packet.Num;
        QTableWidgetItem * tp0=new QTableWidgetItem();
        tp0->setData(Qt::EditRole,function_num);
        tp0->setFlags(tp0->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,0,tp0);

        QTableWidgetItem * tp1=new QTableWidgetItem(new_packet.captured_time);
        tp1->setFlags(tp1->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,1,tp1);

        function_num=new_packet.caplen;
        QTableWidgetItem * tp2=new QTableWidgetItem();
        tp2->setData(Qt::EditRole,function_num);
        tp2->setFlags(tp2->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,2,tp2);

        function_num=new_packet.caplen;
        QTableWidgetItem * tp3=new QTableWidgetItem();
        tp3->setData(Qt::EditRole,function_num);
        tp3->setFlags(tp3->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,3,tp3);

        QTableWidgetItem * tp4=new QTableWidgetItem(QString("%1-%2-%3-%4-%5-%6")
                                                    .arg(new_packet.ethernet_header->source_mac[0],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->source_mac[1],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->source_mac[2],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->source_mac[3],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->source_mac[4],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->source_mac[5],2,16,QChar('0')));
        tp4->setFlags(tp4->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,4,tp4);

        QTableWidgetItem * tp5=new QTableWidgetItem(QString("%1-%2-%3-%4-%5-%6")
                                                    .arg(new_packet.ethernet_header->destant_mac[0],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->destant_mac[1],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->destant_mac[2],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->destant_mac[3],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->destant_mac[4],2,16,QChar('0'))
                .arg(new_packet.ethernet_header->destant_mac[5],2,16,QChar('0')));
        tp5->setFlags(tp5->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,5,tp5);

        QTableWidgetItem * tp6=new QTableWidgetItem(new_packet.protocol);
        tp6->setFlags(tp6->flags() & ~Qt::ItemIsEditable);
        this->setItem(row,6,tp6);

        if(new_packet.protocol.section("/",0,0)=="ARP")
        {
            QTableWidgetItem * tp7=new QTableWidgetItem(QString("%1.%2.%3.%4")
                                                        .arg(new_packet.arp_header->arp_source_ip[0],2,10,QChar(' '))
                    .arg(new_packet.arp_header->arp_source_ip[1],2,10,QChar(' '))
                    .arg(new_packet.arp_header->arp_source_ip[2],2,10,QChar(' '))
                    .arg(new_packet.arp_header->arp_source_ip[3],2,10,QChar(' ')));
            tp7->setFlags(tp7->flags() & ~Qt::ItemIsEditable);
            this->setItem(row,7,tp7);

            QTableWidgetItem * tp8=new QTableWidgetItem(QString("%1.%2.%3.%4")

                                                        .arg(new_packet.arp_header->arp_destant_ip[0],2,10,QChar(' '))
                    .arg(new_packet.arp_header->arp_destant_ip[1],2,10,QChar(' '))
                    .arg(new_packet.arp_header->arp_destant_ip[2],2,10,QChar(' '))
                    .arg(new_packet.arp_header->arp_destant_ip[3],2,10,QChar(' ')));
            tp8->setFlags(tp8->flags() & ~Qt::ItemIsEditable);
            this->setItem(row,8,tp8);

        }
        if(new_packet.protocol.section("/",0,0)=="IP")
        {
            QTableWidgetItem * tp7=new QTableWidgetItem(QString("%1.%2.%3.%4")
                                                        .arg(new_packet.ip_header->source_ip[0],3,10,QChar(' '))
                    .arg(new_packet.ip_header->source_ip[1],3,10,QChar(' '))
                    .arg(new_packet.ip_header->source_ip[2],3,10,QChar(' '))
                    .arg(new_packet.ip_header->source_ip[3],3,10,QChar(' ')));
            tp7->setFlags(tp7->flags() & ~Qt::ItemIsEditable);
            this->setItem(row,7,tp7);

            QTableWidgetItem * tp8=new QTableWidgetItem(QString("%1.%2.%3.%4")
                                                        .arg(new_packet.ip_header->destant_ip[0],3,10,QChar(' '))
                    .arg(new_packet.ip_header->destant_ip[1],3,10,QChar(' '))
                    .arg(new_packet.ip_header->destant_ip[2],3,10,QChar(' '))
                    .arg(new_packet.ip_header->destant_ip[3],3,10,QChar(' ')));
            tp8->setFlags(tp8->flags() & ~Qt::ItemIsEditable);
            this->setItem(row,8,tp8);
        }
        row++;
    }
}
