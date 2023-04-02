#include "utils.h"
QString ip6tos(ipv6_address address)
{
    QString str = QString("%1%2:%3%4:%5%6:%7%8:%9%10:%11%12:%13%14:%15%16")
                      .arg(address.byte1, 0, 16)
                      .arg(address.byte2, 0, 16)
                      .arg(address.byte3, 0, 16)
                      .arg(address.byte4, 0, 16)
                      .arg(address.byte5, 0, 16)
                      .arg(address.byte6, 0, 16)
                      .arg(address.byte7, 0, 16)
                      .arg(address.byte8, 0, 16)
                      .arg(address.byte9, 0, 16)
                      .arg(address.byte10, 0, 16)
                      .arg(address.byte11, 0, 16)
                      .arg(address.byte12, 0, 16)
                      .arg(address.byte13, 0, 16)
                      .arg(address.byte14, 0, 16)
                      .arg(address.byte15, 0, 16)
                      .arg(address.byte16, 0, 16);

    return str;
}
QString mactos(mac_address address)
{
    QString str = QString("%1-%2-%3-%4-%5-%6")
                      .arg(address.byte1, 2, 16, QLatin1Char('0'))
                      .arg(address.byte2, 2, 16, QLatin1Char('0'))
                      .arg(address.byte3, 2, 16, QLatin1Char('0'))
                      .arg(address.byte4, 2, 16, QLatin1Char('0'))
                      .arg(address.byte5, 2, 16, QLatin1Char('0'))
                      .arg(address.byte6, 2, 16, QLatin1Char('0'));
    return str.toUpper();
}

QString iptos(struct ip_address address)
{
    QString str = QString("%1.%2.%3.%4")
                      .arg(address.byte1)
                      .arg(address.byte2)
                      .arg(address.byte3)
                      .arg(address.byte4);
    return str;
}

QString generateOutputFromData(unsigned char *data, int len)
{

    QString hexText = QString("0010  ");
    QString asciiText = QString("");
    char buf[6];
    char ch;
    memset(buf, 0, 6);
    for (int i = 1; i < len + 1; i++)
    {
        sprintf(buf, "%.2x ", data[i - 1]);
        hexText += QString(buf);
        ch = data[i - 1];
        if (isprint(ch))
        {
            asciiText += ch;
        }
        else
        {
            asciiText += '.';
        }
        if ((i % 16) == 0)
        {
            hexText += "\t" + asciiText + "\n";
            hexText += QString("%1  ").arg((i / 16 + 1) * 10, 4, 10, QLatin1Char('0'));
            asciiText = "";
        }

        memset(buf, 0, 6);
    }
    return hexText;
}

QString escape(QString origin)
{
    QString replaced(origin);
    replaced.replace(QString("\r"), QString("\\r"));
    replaced.replace(QString("\n"), QString("\\n"));
    return replaced;
}