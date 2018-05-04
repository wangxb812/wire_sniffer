#include "packet_sender_arp.h"
#include "ui_packet_sender_arp.h"

packet_sender_arp::packet_sender_arp(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::packet_sender_arp)
{
    ui->setupUi(this);
    setWindowTitle("ARP");
}

packet_sender_arp::~packet_sender_arp()
{
    delete ui;
}

void packet_sender_arp::on_btn_begin_clicked()
{
    pcap_if_t *alldevs, *d;
    u_int inum, i=0;
    char errbuf[PCAP_ERRBUF_SIZE];

    QString Router_IP_QString=ui->Router_IP->text();
    QString CHEAT_IP_QString=ui->disguise_IP->text();
    char Router_IP[32];
    char CHEAT_IP[32];
    if(!Router_IP_QString.isEmpty()&&!CHEAT_IP_QString.isEmpty())
    {
        strcpy(Router_IP,Router_IP_QString.toStdString().c_str());
        strcpy(CHEAT_IP,CHEAT_IP_QString.toStdString().c_str());

        pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);

        /* Find the device */
        int j=1;
        for(d=alldevs; d; d=d->next)
        {
            QString device_name=QString("%1").arg(d->name);
            if(device_name==chosen_device) inum=j;
            j++;
        }
        for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

        TA=new thread_arp();
        TA->init(d,0,Router_IP,2,CHEAT_IP);
        TA->start();
        ui->btn_begin->setDisabled(true);
    }
    else
    {
        QMessageBox::warning(this,"WARNING","请输入以上所有信息！！",QMessageBox::Yes);
    }

}

void packet_sender_arp::on_btn_next_clicked()
{

   this->accept();

}
