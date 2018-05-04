#include "welcome.h"
#include "ui_welcome.h"

welcome::welcome(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::welcome)
{
    ui->setupUi(this);
    get_Devices();
}

welcome::~welcome()
{
    delete ui;
}
void welcome:: get_Devices()
{    /* 获取本地机器设备列表 */
    pcap_if_t *alldevs = nullptr;
    pcap_if_t *d = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    int i=0,num=0;
    ui->table->setColumnCount(2);
    QStringList header;
    header<<"Name"<<"Description";
    ui->table->setHorizontalHeaderLabels(header);
    for (d = alldevs;d != NULL;d=d->next)
    {
        num++;
    }
    ui->table->setRowCount(num);
    for (d = alldevs;d != NULL;d=d->next)
    {
        printf("%d. %s", i++, d->name);
        ui->table->setItem(i-1,0,new QTableWidgetItem(d->name));
        if (d->description)
        {
            printf(" (%s)\n", d->description);
            ui->table->setItem(i-1,1,new QTableWidgetItem(d->description));
        }
        else
            printf(" (No description available)\n");

    }
    ui->table->resizeColumnsToContents();
    ui->table->resizeRowsToContents();
    if (i == 0)
    {
        printf("\n No interfaces found!\n");
        exit(1);
    }
    //freede
    pcap_freealldevs(alldevs);
}


void welcome::on_table_itemDoubleClicked(QTableWidgetItem *item)
{
    proName = ui->table->item(ui->table->currentRow(),0)->text();
    this->accept();
}
