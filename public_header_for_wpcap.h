#ifndef PUBLIC_HEADER_FOR_WPCAP_H
#define PUBLIC_HEADER_FOR_WPCAP_H


#include "iostream"
#include "set"
#include "vector"
#include "stdlib.h"
#include "stdio.h"
#include "time.h"
#include "windows.h"
#include "winbase.h"

using namespace std;


#define HAVE_REMOTE
#define WPCAP

#include "Qpcap/pcap/pcap.h"
#include "Qpcap/Packet32.h"

#define LINE_LEN 16

#endif // PUBLIC_HEADER_FOR_WPCAP_H
