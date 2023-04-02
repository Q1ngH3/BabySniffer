#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include <QItemSelection>
#include <QVector>

#include "captureThread.h"
#include "packetslistview.h"
#include "detailtreeview.h"
#include "utils.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
    class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void setConnect();
    void showAllDevices();

public slots:
    void startCapture();
    void stop();
    void addDataToWidget(const QItemSelection &nowSelect);
    void setFilterString();
//    void clearFilterString();

private:
    Ui::MainWindow *ui;
    CaptureThread capture;
    PacketsListView pktltView;
};

#endif // MAINWINDOW_H
