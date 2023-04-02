#ifndef PROTOCOLPROCESS_H
#define PROTOCOLPROCESS_H
#include <QByteArray>
#include <QMessageBox>
#include <QString>
#include "protocol.h"
#include "global.h"
#include "packetslistview.h"
#include "utils.h"
class ProtocolProcess
{
public:
    ProtocolProcess();
    static void processPacket(const struct pcap_pkthdr *header, const unsigned char *data);
    static void processEtherPacket(const unsigned char *);
    static void processIPPacket(const unsigned char *);
    static void processIPv6Packet(const unsigned char *);
    static void processARPPacket(const unsigned char *);
    static void processICMPPacket(const unsigned char *);
    static void processICMPv6Packet(const unsigned char *);
    static void processIGMPPacket(const unsigned char *);

    static void processUDPPacket(const unsigned char *);

    static void processTCPPacket(const unsigned char *);

    static void processHTTPPacket(const unsigned char *);
    static void processHTTPSPacket(const unsigned char *data);
    static void processFTPPacket(const unsigned char *data);
    static void processDNSPacket(const unsigned char *data);
    static void processBasicInfo(const struct pcap_pkthdr *header);

private:
    static AnalyseProtoType parseData;
    static SnifferData displayData;
    static unsigned int ip_len;
};

#endif // PROTOCOLPROCESS_H
