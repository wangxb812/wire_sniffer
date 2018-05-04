#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QString proName,QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("Sniffer");
    ui->label_device->setText(proName);
    //get_packets();
    ui->btn_End->setEnabled(false);

     QVBoxLayout *vbox1 = new QVBoxLayout;
     Pt=new packet_table;
     vbox1->addWidget(Pt);
     ui->groupBox_4->setLayout(vbox1);

     QVBoxLayout *vbox2 = new QVBoxLayout;
     Ptree=new packet_tree;
     vbox2->addWidget(Ptree);
     ui->groupBox_3->setLayout(vbox2);

     Pc=new packet_capture;
     connect(this,SIGNAL(begin()),Pc,SLOT(Begin_capture()));
     connect(Pc,&packet_capture::new_packet,
             this,&MainWindow::Get_latest_packet);
     connect(Pt,&packet_table::clicked,
             this,&MainWindow::packet_clicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::packet_clicked(int clicked_pkt_No)
{
    //qDebug()<<"clicked_packet NO"<<clicked_pkt_No<<endl;

    QString String_to_show;
    for(auto iter:packets)
    {
        if(clicked_pkt_No==iter.Num)
        {
            String_to_show=iter.toQString();
            //iter.print_packet();
            Ptree->clear();
            Ptree->set_header(iter);
        }
        ui->Packet_text->setText(String_to_show);
    }
}
void MainWindow::set_all_nums()
{
    ARP=0;ui->ARP->clear();
    TCP=0;ui->TCP->clear();
    UDP=0;ui->UDP->clear();
    ICMP=0;ui->ICMP->clear();
    HTTP=0;ui->HTTP->clear();
    OTHER=0;ui->OTHER->clear();
    ui->TOTAL->clear();

    for(auto iter:packets)
    {
        if(iter.protocol.section("/",0,0)=="ARP") ARP++;
        if(iter.protocol.section("/",0,0)=="IP")
        {
            if(iter.protocol.section("/",1,1)=="OTHER") UDP++;
            if(iter.protocol.section("/",1,1)=="UDP") UDP++;
            if(iter.protocol.section("/",1,1)=="ICMP") ICMP++;
            if(iter.protocol.section("/",1,1)=="TCP")
            {
                TCP++;
                if(iter.protocol.section("/",2,2)=="HTTP") HTTP++;
            }

        }
        if(iter.protocol.section("/",0,0)=="OTHER") OTHER++;
    }

    ui->ARP->setText(QString::number(ARP,10));
    ui->TCP->setText(QString::number(TCP,10));
    ui->UDP->setText(QString::number(UDP,10));
    ui->ICMP->setText(QString::number(ICMP,10));
    ui->HTTP->setText(QString::number(HTTP,10));
    ui->OTHER->setText(QString::number(OTHER,10));
    ui->TOTAL->setText(QString::number(packets.size(),10));
}

void MainWindow::on_btn_Begin_clicked()
{
    ui->btn_End->setEnabled(true);
    ui->btn_Begin->setEnabled(false);
    emit begin();
}

void MainWindow::on_btn_End_clicked()
{
    ui->btn_End->setEnabled(false);
    ui->btn_Begin->setEnabled(true);
    Pc->Stop_capture();
}

void MainWindow::on_btn_Clear_clicked()
{
    if(fulled)
    {
        ui->btn_End->setEnabled(false);
        ui->btn_Begin->setEnabled(true);
    }
    //this->printed=0;
    packets.clear();
    No=0;

    ui->Packet_text->clear();
    Ptree->clear();

    Pt->clear();
    Pt->setRowCount(1);
    Pt->row=0;
    QStringList header;
    header<<"编号"<<"捕获时间"<<"捕获长度"<<"应有长度"<<"源MAC地址"<<"目的MAC地址"<<"协议类型"<<"源IP地址"<<"目的IP地址";
    Pt->setHorizontalHeaderLabels(header);

    ARP=0;ui->ARP->clear();
    TCP=0;ui->TCP->clear();
    UDP=0;ui->UDP->clear();
    ICMP=0;ui->ICMP->clear();
    HTTP=0;ui->HTTP->clear();
    OTHER=0;ui->OTHER->clear();
    ui->TOTAL->clear();
}

void MainWindow::on_btn_Save_clicked()
{
    QDateTime current_date_time =QDateTime::currentDateTime();
    QString current_date =current_date_time.toString("yyyy.MM.dd hh:mm:ss.zzz ddd");
    QString fileName = QFileDialog::getSaveFileName(this,"另存为");
    QFile file(fileName);
    if (!file.open(QFile::WriteOnly | QFile::Text))
    {
        QMessageBox::warning(this, "警告",QString("无法写入文件 %1：\n %2").arg(fileName).arg(file.errorString()));
        return ;
    }
    QTextStream out(&file);
    QApplication::setOverrideCursor(Qt::WaitCursor);
    out<<"Packet Save time:"+current_date<<endl;
    out<<"Packet filter is:"<<this->filter<<endl;
    out<<"BEGIN"<<endl;
    for(auto iter:packets)
    {
        out<<"Packet NO:"<<iter.Num<<endl;
        out<<"Packet captured time:"<<iter.captured_time<<endl;
        out<<iter.toQString()<<endl;
    }
    QApplication::restoreOverrideCursor();
    QMessageBox::about(this,"ABOUT","文件已经保存完毕！");
    return ;
}
void MainWindow::Get_latest_packet(struct pcap_pkthdr *header,const u_char *pkt_data)
{
    if(No<=5000)
    {
        packet_get new_packet(No,header,pkt_data);
        packets.insert(new_packet);
        Pt->refresh_list(new_packet);
        set_all_nums();
        No++;

    }
    else
    {
        ui->btn_End->setEnabled(false);
        ui->btn_Begin->setEnabled(false);
        Pc->Stop_capture();
        fulled=true;
        //        if(!printed)
        //        {
        //            QMessageBox::warning(this,"Warning","捕获包已满，请清空后重新抓包！");
        //            printed=1;
        //        }
    }
}
void MainWindow::on_Save_clicked()
{

}
