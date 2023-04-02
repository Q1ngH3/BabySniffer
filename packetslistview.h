#ifndef PACKETSLISTVIEW_H
#define PACKETSLISTVIEW_H
#include <QStandardItemModel>
#include "protocol.h"
#include "global.h"
class PacketsListView
{
public:
    PacketsListView();
    static void addPacketItem(SnifferData item);
    void setListHeader();

    static QStandardItemModel *PacketModel;
};

#endif // PACKETSLISTVIEW_H
