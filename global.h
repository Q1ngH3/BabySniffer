#ifndef GLOBAL_H
#define GLOBAL_H
#include <QVector>
#include <QString>
#include "protocol.h"

class Global
{
public:
    Global();
    static QVector<SnifferData> packets;
    static int szNum;
    static QString filter;
};

#endif // GLOBAL_H
