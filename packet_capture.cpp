#include "packet_capture.h"

packet_capture::packet_capture():QObject(nullptr)
{
    m_thread.start();
    this->moveToThread(&m_thread);
    capture_flag = false;
}

int packet_capture::Begin_capture()
{
    pcap_if_t *alldevs,*d;
    pcap_t *fp;
    u_int inum,i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    int res;
    struct bpf_program filter;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    const char * filter_app=packet_filter.toStdString().data();

    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    while (!capture_flag)
        {
             /* Get all the device */
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

            /* Open the device */
            fp= pcap_open(d->name,
                          65537 /*snaplen*/,
                          PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                          20 /*read timeout*/,
                          NULL /* remote authentication */,
                          errbuf);

            pcap_lookupnet(chosen_device.toStdString().data(),
                           &net,
                           &mask,
                           errbuf);

            pcap_compile(fp,
                         &filter,
                         filter_app,
                         1,
                         net);

            if (pcap_setfilter(fp, &filter)<0)
            {
                qDebug()<<"Fail Setting filter！";
            }
            else
            {
                qDebug()<<"Success set filter ！";
            }


            /* Read the packets */
            while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0&&!capture_flag)
            {
                if(res == 0) /* Timeout elapsed */
                    continue;
                emit new_packet(header,pkt_data);
            }

            if(res == -1)
            {
                printf("Error reading the packets: %s\n", pcap_geterr(fp));
                return -1;
            }
            pcap_close(fp);
            pcap_freealldevs(alldevs);

        }
        capture_flag = false;
}

void packet_capture::Stop_capture()
{
    capture_flag = true;
}
