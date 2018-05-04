#include "mainwindow.h"
#include "welcome.h"
#include "packet_filter.h"
#include "packet_sender_arp.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    welcome d;
    QString chosen_device;
    QString filter;
    /*if(w.exec()==QDialog::Accepted)
    {
        MainWindow u(w.proName);
        //qDebug()<<u.proName;
        u.show();
        return a.exec();
    }

    if(w.exec()==QDialog::Accepted)
    {
       packet_filter * pf=new packet_filter;
       pf->setfilter(w.proName);
       if(pf->exec()==QDialog::Accepted)
       {
          filter=pf->get_packet_filter();
           //qDebug()<<packet_filter;
          MainWindow u(w.proName);
          u.show();
          return a.exec();
        }
      else return 0;
     }
     */
    if(d.exec()==QDialog::Accepted)
    {
        chosen_device=d.proName;//qDebug()<<chosen_device;
        packet_sender_arp * Ps=new packet_sender_arp;Ps->setfilter(chosen_device);
        if(Ps->exec()==QDialog::Accepted)
        {
            packet_filter * pf=new packet_filter;
            pf->setfilter(chosen_device);
            if(pf->exec()==QDialog::Accepted)
            {
                filter=pf->get_packet_filter();
                MainWindow w(d.proName);
                w.setfilter(chosen_device,filter);
                w.show();
                return a.exec();
            }
            else return 0;
        }
        else return 0;
    }
    else return 0;
}
