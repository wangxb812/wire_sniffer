#ifndef WELCOME_H
#define WELCOME_H

#include <QDialog>
#include <QTableWidgetItem>
#include "qdebug.h"
#include "public_header_for_wpcap.h"
#include "mainwindow.h"
namespace Ui {
class welcome;
}

class welcome : public QDialog
{
    Q_OBJECT

public:
    explicit welcome(QWidget *parent = 0);
    ~welcome();
    void get_Devices();
    QString proName;
private slots:


    void on_table_itemDoubleClicked(QTableWidgetItem *item);

private:
    Ui::welcome *ui;
};

#endif // WELCOME_H
