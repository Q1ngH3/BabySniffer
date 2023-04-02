#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QList>
#include <QModelIndex>
#include <string>
#include <QHeaderView>
#include <QListWidget>
#include <QComboBox>
#include <QSplitter>
#include <ctype.h>
#include <pcap.h>
#include "captureThread.h"
#include <ifdef.h>
#include <netioapi.h>

using std::string;

QList<string> devicesName;
char errbuf[PCAP_ERRBUF_SIZE];
int interface_selected;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QFont font = QFont("Consolas", 10);
    this->setFont(font);
    showAllDevices();
    ui->stopButton->setDisabled(true);
    ui->packetTableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    ui->packetTableView->verticalHeader()->hide();
    ui->packetTableView->setModel(PacketsListView::PacketModel);
    ui->packetTableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->packetTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    ui->detailTreeView->setModel(DetailTreeView::detailModel);

    setConnect();
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::setConnect() {
    QObject::connect(ui->packetTableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this, SLOT(addDataToWidget(const QItemSelection &)));
    connect(ui->startButton, SIGNAL(clicked()), this, SLOT(startCapture()));
    connect(ui->stopButton, SIGNAL(clicked()), this, SLOT(stop()));
    connect(ui->filterButton, SIGNAL(clicked()), this, SLOT(setFilterString()));
}

static int gethexdigit(const char *p) {
    if(*p >= '0' && *p <= '9'){
        return *p - '0';
    }else if(*p >= 'A' && *p <= 'F'){
        return *p - 'A' + 0xA;
    }else if(*p >= 'a' && *p <= 'f'){
        return *p - 'a' + 0xa;
    }else{
        return -1; /* Not a hex digit */
    }
}

bool get8hexdigits(const char *p, DWORD *d) {
    int digit;
    DWORD val;
    int i;

    val = 0;
    for(i = 0; i < 8; i++){
        digit = gethexdigit(p++);
        if(digit == -1){
            return FALSE; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *d = val;
    return TRUE;
}

bool get4hexdigits(const char *p, WORD *w) {
    int digit;
    WORD val;
    int i;

    val = 0;
    for(i = 0; i < 4; i++){
        digit = gethexdigit(p++);
        if(digit == -1){
            return FALSE; /* Not a hex digit */
        }
        val = (val << 4) | digit;
    }
    *w = val;
    return TRUE;
}

/*
 * If a string is a GUID in {}, fill in a GUID structure with the GUID
 * value and return TRUE; otherwise, if the string is not a valid GUID
 * in {}, return FALSE.
 */
bool parse_as_guid(const char *guid_text, GUID *guid) {
    int i;
    int digit1, digit2;

    if(*guid_text != '{'){
        return FALSE; /* Nope, not enclosed in {} */
    }
    guid_text++;
    /* There must be 8 hex digits; if so, they go into guid->Data1 */
    if(!get8hexdigits(guid_text, &guid->Data1)){
        return FALSE; /* nope, not 8 hex digits */
    }
    guid_text += 8;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data2 */
    if(!get4hexdigits(guid_text, &guid->Data2)){
        return FALSE; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* There must be 4 hex digits; if so, they go into guid->Data3 */
    if(!get4hexdigits(guid_text, &guid->Data3)){
        return FALSE; /* nope, not 4 hex digits */
    }
    guid_text += 4;
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /*
     * There must be 4 hex digits; if so, they go into the first 2 bytes
     * of guid->Data4.
     */
    for(i = 0; i < 2; i++){
        digit1 = gethexdigit(guid_text);
        if(digit1 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if(digit2 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i] = (digit1 << 4)|(digit2);
    }
    /* Now there must be a hyphen */
    if(*guid_text != '-'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /*
     * There must be 12 hex digits; if so,t hey go into the next 6 bytes
     * of guid->Data4.
     */
    for(i = 0; i < 6; i++){
        digit1 = gethexdigit(guid_text);
        if(digit1 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        digit2 = gethexdigit(guid_text);
        if(digit2 == -1){
            return FALSE; /* Not a hex digit */
        }
        guid_text++;
        guid->Data4[i+2] = (digit1 << 4)|(digit2);
    }
    /* Now there must be a closing } */
    if(*guid_text != '}'){
        return FALSE; /* Nope */
    }
    guid_text++;
    /* And that must be the end of the string */
    if(*guid_text != '\0'){
        return FALSE; /* Nope */
    }
    return TRUE;
}

/**********************************************************************************/
#define IF_MAX_STRING_SIZE 256
#define IF_MAX_PHYS_ADDRESS_LENGTH 32
#define NDIS_IF_MAX_STRING_SIZE IF_MAX_STRING_SIZE
/* Get the friendly name for the given GUID */
char* get_interface_friendly_name_from_device_guid(GUID *guid) {
    HRESULT hr;

    /* Need to convert an Interface GUID to the interface friendly name (e.g. "Local Area Connection")
    * The functions required to do this all reside within iphlpapi.dll
    */

    NET_LUID InterfaceLuid;
    hr = ConvertInterfaceGuidToLuid(guid, &InterfaceLuid);
    if(hr == NO_ERROR) {
        /* guid->luid success */
        WCHAR wName[NDIS_IF_MAX_STRING_SIZE + 1];
        hr = ConvertInterfaceLuidToAlias(&InterfaceLuid, wName, NDIS_IF_MAX_STRING_SIZE+1);
        if(hr == NO_ERROR) {
            /* luid->friendly name success */

            /* Get the required buffer size, and then convert the string
            * from UTF-16 to UTF-8. */
            int size;
            char *name;
            size = WideCharToMultiByte(CP_UTF8, 0, wName, -1, NULL, 0, NULL, NULL);
            if(size != 0) {
                name = (char *) calloc(1, size);
                if (name != NULL) {
                    size = WideCharToMultiByte(CP_UTF8, 0, wName, -1, name, size, NULL, NULL);
                    if(size != 0) {
                        return name;
                    }
                    /* Failed, clean up the allocation */
                    free(name);
                }
            }
        }
    }

    /* Failed to get a name */
    return NULL;
}

/*
 * Given an interface name, try to extract the GUID from it and parse it.
 * If that fails, return NULL; if that succeeds, attempt to get the
 * friendly name for the interface in question.  If that fails, return
 * NULL, otherwise return the friendly name, allocated with g_malloc()
 * (so that it must be freed with g_free()).
 */
char *
get_windows_interface_friendly_name(const char *interface_devicename) {
    const char* guid_text;
    GUID guid;

    /* Extract the guid text from the interface device name */
    if (strncmp("rpcap://\\Device\\NPF_", interface_devicename, 20) == 0) {
//        printf("[+] name: %s\n", interface_devicename);
        guid_text=interface_devicename+20; /* skip over the '\Device\NPF_' prefix, assume the rest is the guid text */
    } else {
        guid_text=interface_devicename;
    }

    if (!parse_as_guid(guid_text, &guid)) {
        return NULL; /* not a GUID, so no friendly name */
    }

    /* guid okay, get the interface friendly name associated with the guid */
    return get_interface_friendly_name_from_device_guid(&guid);
}

void MainWindow::showAllDevices() {
    pcap_if_t *alldevs, *d;
    int i = 0;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
        QMessageBox::warning(this, "Error in pcap_findalldevs_ex: %s\n", errbuf);
    }

    for (d = alldevs; d; d = d->next, i++) {
//        printf("[+] name: %s, desc: %s\n", get_windows_interface_friendly_name(d->name), d->description);
        devicesName.push_back(d->name);
        ui->comboBox->addItem(get_windows_interface_friendly_name(d->name));
    }
    pcap_freealldevs(alldevs);
}

void MainWindow::setFilterString() {
    Global::filter = ui->filterlineEdit->text();
    if (Global::filter == "") {
        QMessageBox::warning(this, "warning", "Please input a vaild filter string\n");
        return;
    }
    ui->filterButton->setDisabled(true);
}

void MainWindow::startCapture() {
    QString adapter_name = ui->comboBox->currentText();
    interface_selected = ui->comboBox->currentIndex();

    if (interface_selected == -1) {
        QMessageBox::warning(this, "Select a interface", "Please select a interface first\n");
        return;
    }

    if (!capture.isRunning()) {
        capture.start();
    }

    ui->startButton->setDisabled(true);
    ui->stopButton->setDisabled(false);
}

void MainWindow::stop() {
    ui->stopButton->setDisabled(true);
    ui->startButton->setDisabled(false);
    capture.stop();
}

void MainWindow::addDataToWidget(const QItemSelection &nowSelect) {
    QModelIndexList items = nowSelect.indexes();
    QModelIndex index = items.first();

    int iNumber = index.row();

    if ((unsigned int)iNumber < Global::packets.size()) {
        DetailTreeView::ShowTreeAnalyseInfo(&(Global::packets.at(iNumber)));
        QString output;
        int len = Global::packets.at(iNumber).strLength.toInt();

        // printf("[+] %d %p %d ----------\n", iNumber, Global::packets.at(iNumber).pkt_data, len);
        // for (int k = 0; k < 66; k++) {//输出每个包的前66个byte数据
        //     if (k % 16 == 0 && k != 0)
        //         printf("\n");
        //     printf("%02x ", *(Global::packets.at(iNumber).pkt_data + k));
        // }
        // printf("\n[+] -------------\n");

        output = generateOutputFromData(Global::packets.at(iNumber).pkt_data, len);
        ui->textEdit->setText(output);
    }
}
