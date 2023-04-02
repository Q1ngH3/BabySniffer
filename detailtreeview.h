#ifndef DETAILTREEVIEW_H
#define DETAILTREEVIEW_H

#include <QStandardItemModel>
#include <QString>
#include <QRegularExpression>
#include "protocol.h"
#include "utils.h"
class DetailTreeView
{
public:
    DetailTreeView();
    static void Setup();
    static void ShowTreeAnalyseInfo(const SnifferData *snifferData);
    static void addEthernetInfo(const SnifferData *snifferData);

    static void addNetworkInfo(const SnifferData *snifferData);

    static void addTransInfo(const SnifferData *snifferData);

    static void addAppInfo(const SnifferData *snifferData);
    static void addIPv4Info(const SnifferData *snifferData);
    static void addIPv6Info(const SnifferData *snifferData);
    static void addTCPInfo(QStandardItem *item, const SnifferData *snifferData);
    static void addUDPInfo(QStandardItem *item, const SnifferData *snifferData);
    static void addIGMPInfo(QStandardItem *item, const SnifferData *snifferData);

    static void addHTTPInfo(QStandardItem *item, const SnifferData *snifferData);
    static void addARPInfo(const SnifferData *snifferData);
    static QStandardItemModel *detailModel;
};

#endif // DETAILTREEVIEW_H
