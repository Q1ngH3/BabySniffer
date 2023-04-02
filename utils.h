#ifndef UTILS_H
#define UTILS_H

#include <QString>
#include "protocol.h"

QString ip6tos(ipv6_address address);
QString mactos(mac_address address);
QString iptos(struct ip_address address);
QString generateOutputFromData(unsigned char *data, int len);
QString escape(QString origin);
enum Layers
{
    ethernet_layer,
    network_layer,
    trans_layer,
    application_layer
};

#endif // UTILS_H
