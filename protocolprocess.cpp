#include "protocolprocess.h"

ProtocolProcess::ProtocolProcess()
{
}

AnalyseProtoType ProtocolProcess::parseData;
SnifferData ProtocolProcess::displayData;

unsigned int ProtocolProcess::ip_len = 0;
void ProtocolProcess::processPacket(const struct pcap_pkthdr *header, const unsigned char *data) {
    unsigned char* pkt_data = (unsigned char*)calloc(1, header->len + 1);
    memcpy(pkt_data, data, header->len);

    displayData.pkt_data = (unsigned char *)pkt_data;
    parseData.header = (struct pcap_pkthdr *)header;
    QByteArray rawByteData;

    parseData.init();
    processBasicInfo(header);
    processEtherPacket(pkt_data);
    displayData.protoInfo = parseData;
    Global::packets.push_back(displayData);
    PacketsListView::addPacketItem(displayData);
}

void ProtocolProcess::processBasicInfo(const struct pcap_pkthdr *header) {
    char szNum[10];
    struct tm *ltime;
    char timestr[16];
    char szLength[6];
    sprintf(szNum, "%d", Global::szNum);
    displayData.strNum = szNum;
    Global::szNum += 1;
    time_t local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    displayData.strTime = timestr;
    sprintf(szLength, "%d", header->len);
    displayData.strLength = szLength;
}

void ProtocolProcess::processEtherPacket(const unsigned char *data) {
    parseData.ether_header = (ethhdr *)data;
    int ether_type = parseData.ether_header->type;
    switch (ether_type) 
    {
    case 0x0608:
        parseData.strType = "Type: ARP (0x0806)";
        processARPPacket(data);
        break;
    case 0x0008:
        parseData.strType = "Type: IPv4 (0x0800)";
        processIPPacket(data);
        break;
    case 0xdd86:
        parseData.strType = "Type: IPv6 (0x86DD)";
        processIPv6Packet(data);
        break;
    default:
        break;
    }
    QByteArray DMac, SMac;
    DMac.setRawData((const char *)parseData.ether_header->dest, 6);
    SMac.setRawData((const char *)parseData.ether_header->src, 6);

    // parseData.strDMac = parseData.strDMac + bytes2mac(DMac);
    // parseData.strSMac = parseData.strSMac + bytes2mac(SMac);
    DMac = DMac.toHex().toUpper();
    SMac = SMac.toHex().toUpper();
    parseData.strDMac = parseData.strDMac + DMac[0] + DMac[1] + "-" + DMac[2] + DMac[3] + "-" + DMac[4] + DMac[5] + "-" + DMac[6] + DMac[7] + "-" + DMac[8] + DMac[9] + "-" + DMac[10] + DMac[11];
    parseData.strSMac = parseData.strSMac + SMac[0] + SMac[1] + "-" + SMac[2] + SMac[3] + "-" + SMac[4] + SMac[5] + "-" + SMac[6] + SMac[7] + "-" + SMac[8] + SMac[9] + "-" + SMac[10] + SMac[11];
}

void ProtocolProcess::processIPPacket(const unsigned char *data) {
    displayData.strProto = "IP";
    parseData.strNetProto = "IPv4 (Internet Protocol version 4)";
    parseData.IP_header = (iphdr *)(data + SIZE_ETHERNET);
    ip_len = (parseData.IP_header->ver_ihl & 0xF) * 4;
    switch (parseData.IP_header->proto)
    {
    case TCP_SIG:
        processTCPPacket(data);
        break;
    case UDP_SIG:
        processUDPPacket(data);
        break;
    case ICMP_SIG:
        processICMPPacket(data);
        break;
    case IGMP_SIG:
        processIGMPPacket(data);
        break;
    default:
        break;
    }

    char szSize[6];
    sprintf(szSize, "%u", ip_len);
    parseData.strHeadLength += QString(szSize) + QString(" bytes");
    int ip_all_len = ntohs(parseData.IP_header->tlen);
    sprintf(szSize, "%u", ip_all_len);
    parseData.strLength += QString(szSize) + QString(" bytes");

    char szSaddr[24], szDaddr[24];
    sprintf(szSaddr, "%d.%d.%d.%d", parseData.IP_header->saddr[0], parseData.IP_header->saddr[1], parseData.IP_header->saddr[2], parseData.IP_header->saddr[3]);
    sprintf(szDaddr, "%d.%d.%d.%d", parseData.IP_header->daddr[0], parseData.IP_header->daddr[1], parseData.IP_header->daddr[2], parseData.IP_header->daddr[3]);

    displayData.strSIP = QString(szSaddr) + ":" + QString(displayData.strSPort);
    displayData.strDIP = QString(szDaddr) + ":" + QString(displayData.strDPort);

    parseData.strSIP += szSaddr;
    parseData.strDIP += szDaddr;
}

void ProtocolProcess::processIPv6Packet(const unsigned char *data) {
    displayData.strProto = "IP";
    parseData.strNetProto = "IPv6 (Internet Protocol version 6)";
    parseData.IPv6_header = (ipv6hdr *)(data + SIZE_ETHERNET);
    ip_len = 40;

    if (parseData.IPv6_header->next_header == PROTO_TYPE_TCP) {
        processTCPPacket(data);
    } else if (parseData.IPv6_header->next_header == PROTO_TYPE_UDP) {
        processUDPPacket(data);
    } else if (parseData.IPv6_header->next_header == PROTO_TYPE_ICMPv6) {
        processICMPv6Packet(data);
    }
    
    displayData.strSIP = ip6tos(parseData.IPv6_header->source_ip) + ":" + QString(displayData.strSPort);
    displayData.strDIP = ip6tos(parseData.IPv6_header->dest_ip) + ":" + QString(displayData.strDPort);
    parseData.strSIP += ip6tos(parseData.IPv6_header->source_ip);
    parseData.strDIP += ip6tos(parseData.IPv6_header->dest_ip);
}

void ProtocolProcess::processARPPacket(const unsigned char *data) {
    displayData.strProto = "ARP";
    parseData.strNetProto = "ARP (Address Resolution Protocol)";
    parseData.ARP_header = (arphdr *)(data + SIZE_ETHERNET);
}

void ProtocolProcess::processICMPPacket(const unsigned char *data) {
    displayData.strProto = "ICMP";
    parseData.strTranProto = "ICMP (Internet Control Message Protocol)";
    parseData.ICMP_header = (icmphdr *)((unsigned char *)parseData.IP_header + ip_len);
}

void ProtocolProcess::processICMPv6Packet(const unsigned char *data) {
    displayData.strProto = "ICMPv6";
    parseData.strTranProto = "ICMPv6 (Internet Control Message Protocol Version 6)";
}

void ProtocolProcess::processIGMPPacket(const unsigned char *data) {
    displayData.strProto = "IGMP";
    parseData.strTranProto = "IGMP (Internet Group Management Protocol)";

    parseData.IGMP_header = (igmphdr *)((unsigned char *)parseData.IP_header + ip_len);
}

void ProtocolProcess::processUDPPacket(const unsigned char *data) {
    displayData.strProto = "UDP";
    parseData.strTranProto = "UDP (User Datagram Protocol)";
    
    if (parseData.IP_header != nullptr)
        parseData.UDP_header = (udphdr *)((unsigned char *)parseData.IP_header + ip_len);
    else
        parseData.UDP_header = (udphdr *)((unsigned char *)parseData.IPv6_header + ip_len);
    
    unsigned short sport = ntohs(parseData.UDP_header->sport);
    unsigned short dport = ntohs(parseData.UDP_header->dport);
    
    if (sport == DNS_PORT || dport == DNS_PORT) {
        processDNSPacket(data);
    }

    char szSPort[6], szDPort[6];
    sprintf(szSPort, "%d", sport);
    sprintf(szDPort, "%d", dport);
    parseData.strSPort += szSPort;
    parseData.strDPort += szDPort;
    displayData.strSPort = szSPort;
    displayData.strDPort = szDPort;
}

void ProtocolProcess::processTCPPacket(const unsigned char *data) {
    displayData.strProto = "TCP";
    parseData.strTranProto = "TCP (Transmission Control Protocol)";

    if (parseData.IP_header != nullptr)
        parseData.TCP_header = (tcphdr *)((unsigned char *)parseData.IP_header + ip_len);
    else
        parseData.TCP_header = (tcphdr *)((unsigned char *)parseData.IPv6_header + ip_len);
    
    unsigned short sport = ntohs(parseData.TCP_header->sport);
    unsigned short dport = ntohs(parseData.TCP_header->dport);
    
    if (sport == FTP_PORT || dport == FTP_PORT) {
        processFTPPacket(data);
    } else if (sport == HTTPS_PORT || dport == HTTPS_PORT) {
        processHTTPSPacket(data);
    } else if (sport == HTTP_PORT || dport == HTTP_PORT) {
        processHTTPPacket(data);
    }

    char szSPort[6], szDPort[6];
    sprintf(szSPort, "%d", sport);
    sprintf(szDPort, "%d", dport);
    parseData.strSPort += szSPort;
    parseData.strDPort += szDPort;
    displayData.strSPort = szSPort;
    displayData.strDPort = szDPort;
}

void ProtocolProcess::processHTTPPacket(const unsigned char *data) {
    displayData.strProto = "HTTP";
    parseData.strAppProto = "HTTP (Hyper Text Transport Protocol)";
}

void ProtocolProcess::processHTTPSPacket(const unsigned char *data) {
    displayData.strProto = "HTTPS";
    parseData.strAppProto = "HTTPS (Hypertext Transfer "
                            "Protocol over Secure Socket Layer)";
}

void ProtocolProcess::processFTPPacket(const unsigned char *data) {
    displayData.strProto = "FTP";
    parseData.strAppProto = "FTP (File Transfer Protocol)";
}

void ProtocolProcess::processDNSPacket(const unsigned char *data) {
    displayData.strProto = "DNS";
    parseData.strAppProto = "DNS (Domain Name Server)";
}
