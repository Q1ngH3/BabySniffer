#ifndef CAPTURETHREAD_H
#define CAPTURETHREAD_H

#include <QThread>
#include <QString>
#include <QDebug>
#include <QMessageBox>

#include <pcap.h>

class CaptureThread : public QThread
{
    Q_OBJECT

public:
    explicit CaptureThread();
    ~CaptureThread();
    void stop();
    void run();

signals:
    void CaptureStopped();
    
private:
    volatile bool isStopped;
};

#endif // CAPTURETHREAD_H
