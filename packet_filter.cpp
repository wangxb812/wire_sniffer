#include "packet_filter.h"
#include "ui_packet_filter.h"

packet_filter::packet_filter(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::packet_filter)
{
    ui->setupUi(this);
    setWindowTitle("过滤设置");
}

packet_filter::~packet_filter()
{
    delete ui;
}

void packet_filter::on_btn_yes_clicked()
{
    if(ui->is_TCP->isChecked())
    {
        QString_packet_filter+="(ip and tcp) or ";
    }
    if(ui->is_UDP->isChecked())
    {
        QString_packet_filter+="(ip and udp) or ";
    }
    if(ui->is_ARP->isChecked())
    {
        QString_packet_filter+="arp or ";
    }
    if(ui->is_ICMP->isChecked())
    {
        QString_packet_filter+="(ip and icmp) or ";
    }
    if(ui->is_RARP->isChecked())
    {
        QString_packet_filter+="rarp or ";
    }
    if(ui->is_IGMP->isChecked())
    {
        QString_packet_filter+="(ip and igmp) or ";
    }
    QString_packet_filter = QString_packet_filter.left(QString_packet_filter.length()-4);  //注意去掉最后多余的" or ",否则过滤规则不成立
    if(!ui->Input_filter->toPlainText().isEmpty()&&ui->is_myself->isChecked())
        {
            if(!QString_packet_filter.isEmpty())QString_packet_filter+=" and ";
            QString_packet_filter+=ui->Input_filter->toPlainText();
        }
        pcap_if_t *alldevs, *d;
        pcap_t *fp;
        u_int inum, i=0;
        char errbuf[2000];
        struct bpf_program filter;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        const char * filter_app=QString_packet_filter.toStdString().data();


        pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf);
        int j=1;
        for(d=alldevs; d; d=d->next)
        {
            QString device_name=QString("%1").arg(d->name);
            if(device_name==chosen_device) inum=j;
            j++;
        }
        for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

        /* Open the device */
        fp= pcap_open(d->name,
                      100 /*snaplen*/,
                      PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                      20 /*read timeout*/,
                      NULL /* remote authentication */,
                      errbuf);

        if(pcap_lookupnet(chosen_device.toStdString().data(), &net, &mask, errbuf)<0)
        {
            QMessageBox::about(this,"Error","获取网络掩码错误！错误码："+QString("%1").arg(errbuf));
        }
        else
        {
            QMessageBox::about(this,"Congratulations","获取网络掩码成功！");
        }


        if(pcap_compile(fp, &filter, filter_app, 1, net)<0)
        {
            QMessageBox::warning(this,"Check","您的过滤方式存在错误：\n"+
                                 QString_packet_filter+
                                 "请检查！\n",QMessageBox::Yes,QMessageBox::No);
            QString_packet_filter.clear();
        }
        else
        {
            if(QMessageBox::warning(this,"Check","恭喜，您的过滤方式检查通过！\n需要继续编辑么？",QMessageBox::Yes,QMessageBox::No)==QMessageBox::No)
            {
                this->accept();
            }
            else  QString_packet_filter.clear();

        }
}
QString packet_filter::get_packet_filter()
{
    return QString_packet_filter;
}


