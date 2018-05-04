#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"

class packet_capture :public QObject
{
    Q_OBJECT
public:
    packet_capture();
    void setfilter(QString chosen, QString packet)
    {
        this->chosen_device=chosen;this->packet_filter=packet;
       // qDebug()<<chosen_device; qDebug()<<packet_filter;
    }
public slots:
    int Begin_capture();
    void Stop_capture();

signals:
    void new_packet(struct pcap_pkthdr *header,const u_char *pkt_data);

private:
    QThread m_thread;
    QString chosen_device;
    QString packet_filter;

    volatile bool capture_flag;
};

#endif // PACKET_CAPTURE_H
