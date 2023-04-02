#include "detailtreeview.h"

DetailTreeView::DetailTreeView()
{
}
QStandardItemModel *DetailTreeView::detailModel = new QStandardItemModel;

void DetailTreeView::Setup() {
    detailModel->clear();
    detailModel->setColumnCount(1);
    detailModel->setHeaderData(0, Qt::Horizontal, "Analysis Result:");
}

void DetailTreeView::ShowTreeAnalyseInfo(const SnifferData *snifferData) {
    Setup();
    addEthernetInfo(snifferData);
    addNetworkInfo(snifferData);
    addTransInfo(snifferData);
    addAppInfo(snifferData);
}

void DetailTreeView::addEthernetInfo(const SnifferData *snifferData) {
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strEthTitle);
    detailModel->setItem(ethernet_layer, item);
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDMac));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSMac));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strType));
}

void DetailTreeView::addNetworkInfo(const SnifferData *snifferData) {
    QStandardItem *item, *itemChild;

    if (snifferData->protoInfo.strNetProto.indexOf("IPv4") != -1) {
        addIPv4Info(snifferData);
    } else if (snifferData->protoInfo.strNetProto.indexOf("IPv6") != -1) {
        addIPv6Info(snifferData);
    } else if (snifferData->protoInfo.strNetProto.indexOf("ARP") != -1) {
        addARPInfo(snifferData);
    }
}

void DetailTreeView::addIPv4Info(const SnifferData *snifferData) {
    QStandardItem *item = new QStandardItem(snifferData->protoInfo.strNetProto);
    detailModel->setItem(network_layer, item);
    item->appendRow(new QStandardItem(snifferData->protoInfo.strVersion));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strHeadLength));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strLength));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSIP));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDIP));
}

void DetailTreeView::addIPv6Info(const SnifferData *snifferData) {
    ipv6hdr *hdr = snifferData->protoInfo.IPv6_header;
    QStandardItem *item = new QStandardItem(snifferData->protoInfo.strNetProto);
    detailModel->setItem(network_layer, item);
    item->appendRow(new QStandardItem(snifferData->protoInfo.strSIP));
    item->appendRow(new QStandardItem(snifferData->protoInfo.strDIP));
}

void DetailTreeView::addARPInfo(const SnifferData *snifferData) {
    QString hd_type;
    u_short proto_type;
    QString proto_type_str;
    QString hd_len;
    QString pro_addr_len;
    u_short opcode;
    QString opcode_str;
    QString src_addr;
    QString dst_addr;
    QString sip_addr;
    QString dip_addr;

    hd_type = QString::number(ntohs(snifferData->protoInfo.ARP_header->hardware_type));
    proto_type = ntohs(snifferData->protoInfo.ARP_header->protocal_type);
    
    switch (proto_type)
    {
    case ETHER_TYPE_IPv4:
        proto_type_str = QString("IPv4");
        break;
    case ETHER_TYPE_IPv6:
        proto_type_str = QString("IPv6");
        break;
    default:
        proto_type_str = QString("UNKNOWN");
        break;
    }

    hd_len = QString::number(snifferData->protoInfo.ARP_header->hwadd_len);
    pro_addr_len = QString::number(snifferData->protoInfo.ARP_header->proadd_len);
    opcode = ntohs(snifferData->protoInfo.ARP_header->opcode);
    
    switch (opcode)
    {
    case ARPOP_REQUEST:
        opcode_str = QString("ARP Request");
        break;
    case ARPOP_REPLY:
        opcode_str = QString("ARP Reply");
        break;
    case ARPOP_RREQUEST:
        opcode_str = QString("RARP Request.");
        break;
    case ARPOP_RREPLY:
        opcode_str = QString("RARP Reply");
        break;
    default:
        opcode_str = QString("UNKNOWN ARP opcode");
        break;
    }
    
    src_addr = mactos(snifferData->protoInfo.ARP_header->snether_address);
    dst_addr = mactos(snifferData->protoInfo.ARP_header->dnether_address);
    sip_addr = iptos(snifferData->protoInfo.ARP_header->sip_address);
    dip_addr = iptos(snifferData->protoInfo.ARP_header->dip_address);

    QStandardItem *item = new QStandardItem(QString("ARP (Address Resolution Protocol(%1))").arg(opcode_str));
    detailModel->setItem(network_layer, item);

    QList<QStandardItem *> childItems;
    childItems.push_back(new QStandardItem(QString("Hardware type: %1").arg(hd_type)));
    childItems.push_back(new QStandardItem(QString("Protocol type: %1(0x%2)").arg(proto_type_str).arg(proto_type, 4, 16, QChar('0'))));
    childItems.push_back(new QStandardItem(QString("Hardware size: %1").arg(hd_len)));
    childItems.push_back(new QStandardItem(QString("Protocol size: %1").arg(pro_addr_len)));
    childItems.push_back(new QStandardItem(QString("Opcode: %1(%2)").arg(opcode_str).arg(opcode)));
    childItems.push_back(new QStandardItem(QString("Sender MAC address: %1").arg(src_addr)));
    childItems.push_back(new QStandardItem(QString("Sender IP address: %1").arg(sip_addr)));
    childItems.push_back(new QStandardItem(QString("Target MAC address: %1").arg(dst_addr)));
    childItems.push_back(new QStandardItem(QString("Sender MAC address: %1").arg(dip_addr)));
    item->appendRows(childItems);
}

void DetailTreeView::addTransInfo(const SnifferData *snifferData) {
    if (snifferData->protoInfo.strTranProto == "")
        return;
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strTranProto);
    detailModel->setItem(trans_layer, item);

    if (snifferData->protoInfo.strTranProto.indexOf("TCP") != -1) {
        item->appendRow(new QStandardItem(snifferData->protoInfo.strSPort));
        item->appendRow(new QStandardItem(snifferData->protoInfo.strDPort));
        addTCPInfo(item, snifferData);
    } else if (snifferData->protoInfo.strTranProto.indexOf("UDP") != -1) {
        item->appendRow(new QStandardItem(snifferData->protoInfo.strSPort));
        item->appendRow(new QStandardItem(snifferData->protoInfo.strDPort));
        addUDPInfo(item, snifferData);
    } else if (snifferData->protoInfo.strTranProto.indexOf("IGMP") != -1) {
        addIGMPInfo(item, snifferData);
    }
}

void DetailTreeView::addTCPInfo(QStandardItem *item, const SnifferData *snifferData) {
    QString data_offset = QString::number((ntohs(snifferData->protoInfo.TCP_header->tcp_res) & 0xf000) >> 12);
    u_short flags = ntohs(snifferData->protoInfo.TCP_header->tcp_res) & 0x003f;
    u_short URG = flags & 0x0020;
    u_short ACK = flags & 0x0010;
    u_short PSH = flags & 0x0008;
    u_short RST = flags & 0x0004;
    u_short SYN = flags & 0x0002;
    u_short FIN = flags & 0x0001;
    QString seq_num = QString::number(ntohs(snifferData->protoInfo.TCP_header->seq));
    QString ack_num = QString::number(ntohs(snifferData->protoInfo.TCP_header->ack));
    QString window_size = QString::number(ntohs(snifferData->protoInfo.TCP_header->windsize));
    QString crc = QString::number(ntohs(snifferData->protoInfo.TCP_header->crc));
    QString urgp = QString(ntohs(snifferData->protoInfo.TCP_header->urgp));

    QList<QStandardItem *> childItems;

    childItems.push_back(new QStandardItem(QString("Sequence Number: %1").arg(seq_num)));
    childItems.push_back(new QStandardItem(QString("ACK number: %1").arg(ack_num)));
    childItems.push_back(new QStandardItem(QString("Header length: %1").arg(4 * data_offset.toInt())));
    childItems.push_back(new QStandardItem(QString("Flags: %1").arg(flags)));
    childItems.push_back(new QStandardItem(QString("Window size value: %1").arg(window_size)));
    item->appendRows(childItems);
}

void DetailTreeView::addUDPInfo(QStandardItem *item, const SnifferData *snifferData) {
    QString length = QString::number(ntohs(snifferData->protoInfo.UDP_header->len));
    QString crc = QString::number(ntohs(snifferData->protoInfo.UDP_header->crc));

    QList<QStandardItem *> childItems;
    childItems.push_back(new QStandardItem(QString("Length: %1").arg(length)));
    childItems.push_back(new QStandardItem(QString("Checksum: %1").arg(crc)));
    item->appendRows(childItems);
}

void DetailTreeView::addIGMPInfo(QStandardItem *item, const SnifferData *snifferData) {
    igmphdr *IGMP_header = (igmphdr *)(snifferData->protoInfo.IGMP_header);
    QString crc = QString::number(ntohs(IGMP_header->igmp_cksum));
    QList<QStandardItem *> childItems;
    childItems.push_back(new QStandardItem(QString("Checksum: %1").arg(crc)));
    item->appendRows(childItems);
}

void DetailTreeView::addAppInfo(const SnifferData *snifferData) {
    if (snifferData->protoInfo.strAppProto == "")
        return;
    QStandardItem *item, *itemChild;
    item = new QStandardItem(snifferData->protoInfo.strAppProto);
    detailModel->setItem(application_layer, item);

    if (snifferData->protoInfo.strAppProto.indexOf("HTTP") != -1) {
        addHTTPInfo(item, snifferData);
    }
}

void DetailTreeView::addHTTPInfo(QStandardItem *item, const SnifferData *snifferData) {
//    qDebug() << "I am here";
    QRegularExpression httpGetMethodReg("GET .+\r\n");
    QRegularExpression httpHostReg("Host: .+\r\n");
    QRegularExpression httpConnectionReg("Connection: .+\r\n");
    QRegularExpression httpUserAgentReg("User-Agent: .+\r\n");
    QRegularExpression httpAcceptReg("Accept: .+\r\n");

    QRegularExpression httpDateReg("Date: .+\r\n");
    QRegularExpression httpContentLengthReg("Content-Length: .+\r\n");
    QRegularExpression httpCacheControlReg("Cache-Control: .+\r\n");

    QRegularExpression httpResponseReg("HTTP/1.1 .+\r\n");

    std::string http_txt = "";
    uint16_t ip_len;
//    qDebug() << "[+] " << snifferData->protoInfo.IP_header->tlen;
    if (snifferData->protoInfo.IP_header != NULL) {
        ip_len = ntohs(snifferData->protoInfo.IP_header->tlen);
    } else {
        ip_len = ntohs(snifferData->protoInfo.IPv6_header->load_length);
    }

//    qDebug() << "[-] " << ip_len;
    for (uint16_t i = 0; i < ip_len; ++i) {
        if ((isalnum((snifferData->pkt_data + 14)[i]) || ispunct((snifferData->pkt_data + 14)[i]) ||
             isspace((snifferData->pkt_data + 14)[i]) || isprint((snifferData->pkt_data + 14)[i]))) {
            http_txt += (snifferData->pkt_data + 14)[i];
        }
    }
    
    QString text = QString(http_txt.c_str());
    QString httpMethod, httpHost, httpConnection, httpCacheControl, httpUserAgent, httpAccept, httpResponse;
    QString httpDate, httpContentLength;
    if (httpGetMethodReg.match(text).hasMatch())
        httpMethod = httpGetMethodReg.match(text).captured(0);
    if (httpHostReg.match(text).hasMatch())
        httpHost = httpHostReg.match(text).captured(0);
    if (httpConnectionReg.match(text).hasMatch())
        httpConnection = httpConnectionReg.match(text).captured(0);
    if (httpCacheControlReg.match(text).hasMatch())
        httpCacheControl = httpCacheControlReg.match(text).captured(0);
    if (httpUserAgentReg.match(text).hasMatch())
        httpUserAgent = httpUserAgentReg.match(text).captured(0);
    if (httpAcceptReg.match(text).hasMatch())
        httpAccept = httpAcceptReg.match(text).captured(0);
    if (httpResponseReg.match(text).hasMatch())
        httpResponse = httpResponseReg.match(text).captured(0);
    if (httpDateReg.match(text).hasMatch())
        httpDate = httpDateReg.match(text).captured(0);
    if (httpContentLengthReg.match(text).hasMatch())
        httpContentLength = httpContentLengthReg.match(text).captured(0);
    httpMethod = escape(httpMethod);
    httpHost = escape(httpHost);
    httpConnection = escape(httpConnection);
    httpCacheControl = escape(httpCacheControl);
    httpUserAgent = escape(httpUserAgent);
    httpAccept = escape(httpAccept);
    httpResponse = escape(httpResponse);

    QList<QStandardItem *> itemChild;
    if (!httpMethod.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpMethod)));
    if (!httpResponse.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpResponse)));
    if (!httpHost.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpHost)));
    if (!httpConnection.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpConnection)));
    if (!httpUserAgent.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpUserAgent)));
    if (!httpAccept.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpAccept)));
    if (!httpCacheControl.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpCacheControl)));
    if (!httpDate.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpDate)));
    if (!httpContentLength.isEmpty())
        itemChild.push_back(new QStandardItem(QString(httpContentLength)));
//    qDebug() << "itemChild: " << itemChild;
    item->appendRows(itemChild);
}
