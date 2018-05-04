#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include "public_header_for_wpcap.h"
#include "public_qt.h"
#include "packet_get.h"
#include "packet_capture.h"
#include "packet_tree.h"
#include "packet_table.h"

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QString proName,QWidget *parent = 0);
    ~MainWindow();
    QString proName;
    void get_packets();
    void setfilter(QString chosen, QString packet)
    {
        this->proName=chosen;this->filter=packet;
        Pc->setfilter(proName,filter);
        // qDebug()<<chosen_device; qDebug()<<packet_filter;
    }

private slots:

    void Get_latest_packet(struct pcap_pkthdr *header,const u_char *pkt_data);

    void packet_clicked(int clicked_pkt_No);

    void on_btn_Begin_clicked();

    void on_btn_End_clicked();

    void on_btn_Clear_clicked();

    void on_btn_Save_clicked();

    void on_Save_clicked();

signals:
    void begin();

    void clear();
private:
    Ui::MainWindow *ui;
    QString filter;
    packet_capture * Pc;
    packet_table * Pt;
    packet_tree * Ptree;
    bool fulled;
   // bool printed=0;

    int No=0;
    set<packet_get> packets;

    int ARP=0;
    int TCP=0;
    int UDP=0;
    int ICMP=0;
    int HTTP=0;
    int OTHER=0;
    void set_all_nums();
};

#endif // MAINWINDOW_H
