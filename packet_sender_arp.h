#ifndef PACKET_SENDER_ARP_H
#define PACKET_SENDER_ARP_H

#include <QDialog>
#include "thread_arp.h"
namespace Ui {
class packet_sender_arp;
}

class packet_sender_arp : public QDialog
{
    Q_OBJECT

public:
    explicit packet_sender_arp(QWidget *parent = 0);
    ~packet_sender_arp();
    void setfilter(QString chosen)
    {
        this->chosen_device=chosen;
        // qDebug()<<chosen_device; qDebug()<<packet_filter;
    }

private slots:

    void on_btn_begin_clicked();

    void on_btn_next_clicked();

private:
    Ui::packet_sender_arp *ui;
    QString chosen_device;
    thread_arp * TA;
};

#endif // PACKET_SENDER_ARP_H
