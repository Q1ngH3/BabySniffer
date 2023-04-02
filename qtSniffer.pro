QT += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++11

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    detailtreeview.cpp \
    global.cpp \
    main.cpp \
    mainwindow.cpp \
    packetslistview.cpp \
    protocolprocess.cpp \
    captureThread.cpp \
    utils.cpp

HEADERS += \
    detailtreeview.h \
    global.h \
    mainwindow.h \
    packet.h \
    packetslistview.h \
    protocol.h \
    protocolprocess.h \
    captureThread.h \
    utils.h

FORMS += \
    mainwindow.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

INCLUDEPATH += E:/WpdPack/Include
LIBS += -LE:/WpdPack/Lib/x64
LIBS += -lwpcap
LIBS += -lws2_32
LIBS += -lIphlpapi
DEFINES += WPCAP
DEFINES += HAVE_REMOTE
