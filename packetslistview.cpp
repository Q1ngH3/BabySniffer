#include "packetslistview.h"

PacketsListView::PacketsListView() {
    setListHeader();
}

QStandardItemModel *PacketsListView::PacketModel = new QStandardItemModel();

void PacketsListView::addPacketItem(SnifferData data) {
    QStandardItem *item;
    int row = PacketModel->rowCount();
    PacketModel->setItem(row, 0, new QStandardItem(QString(data.strNum)));
    PacketModel->setItem(row, 1, new QStandardItem(QString(data.strTime)));
    PacketModel->setItem(row, 2, new QStandardItem(QString(data.strSIP)));
    PacketModel->setItem(row, 3, new QStandardItem(QString(data.strDIP)));
    PacketModel->setItem(row, 4, new QStandardItem(QString(data.strProto)));
    PacketModel->setItem(row, 5, new QStandardItem(QString(data.strLength)));
}

void PacketsListView::setListHeader() {
    PacketModel->clear();
    PacketModel->setColumnCount(6);
    char *headers[6] = {"No.", "Time", "Source", "Destination", "Protocol", "Length"};
    for (int i = 0; i <= 5; i++) {
        PacketModel->setHeaderData(i, Qt::Horizontal, QString(headers[i]));
    }
}
