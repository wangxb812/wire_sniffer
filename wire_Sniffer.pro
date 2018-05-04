#-------------------------------------------------
#
# Project created by QtCreator 2018-04-19T20:13:13
#
#-------------------------------------------------

QT       += core gui

LIBS+=wpcap.lib Packet.lib
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = wire_Sniffer
TEMPLATE = app

# The following define makes your compiler emit warnings if you use
# any feature of Qt which has been marked as deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0


SOURCES += \
        main.cpp \
        mainwindow.cpp \
    welcome.cpp \
    packet_filter.cpp \
    packet_capture.cpp \
    packet_cat_arp.cpp \
    packet_cat_ethernet.cpp \
    packet_cat_icmp.cpp \
    packet_cat_ip.cpp \
    packet_cat_tcp.cpp \
    packet_cat_udp.cpp \
    packet_cat_http.cpp \
    packet_get.cpp \
    packet_tree.cpp \
    packet_table.cpp \
    thread_arp.cpp \
    packet_sender_arp.cpp

HEADERS += \
        mainwindow.h \
    public_header_for_wpcap.h \
    welcome.h \
    packet_filter.h \
    public_qt.h \
    packet_capture.h \
    packet_cat_arp.h \
    packet_cat_ethernet.h \
    packet_cat_icmp.h \
    packet_cat_ip.h \
    packet_cat_tcp.h \
    packet_cat_udp.h \
    packet_cat_http.h \
    packet_get.h \
    packet_headers.h \
    packet_tree.h \
    packet_table.h \
    thread_arp.h \
    arp_cheating_header.h \
    packet_sender_arp.h

FORMS += \
        mainwindow.ui \
    welcome.ui \
    packet_filter.ui \
    packet_sender_arp.ui
