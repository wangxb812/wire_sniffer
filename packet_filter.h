#ifndef PACKET_FILTER_H
#define PACKET_FILTER_H

#include <QDialog>
#include "public_header_for_wpcap.h"
#include "public_qt.h"
#include <QString>
namespace Ui {
class packet_filter;
}

class packet_filter : public QDialog
{
    Q_OBJECT

public:
    explicit packet_filter(QWidget *parent = 0);
    ~packet_filter();

    QString get_packet_filter();

    void setfilter(QString chosen)
    {
        this->chosen_device=chosen;
       // qDebug()<<chosen_device; qDebug()<<packet_filter;
    }

private slots:
    void on_btn_yes_clicked();

private:
    Ui::packet_filter *ui;
    QString chosen_device;//proname
    QString QString_packet_filter;
};

#endif // PACKET_FILTER_H
