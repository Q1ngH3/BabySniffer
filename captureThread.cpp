#include <QString>
#include <string>
#include "global.h"
#include "protocolprocess.h"
#include "captureThread.h"

using std::string;
extern QList<string> devicesName;
extern int interface_selected;
extern char errbuf[PCAP_ERRBUF_SIZE];
extern QString captureFilterString;

CaptureThread::CaptureThread() {
    isStopped = false;
}

CaptureThread::~CaptureThread() {}

void CaptureThread::stop() {
    isStopped = true;
}

int setFilter(pcap_t *fp, QString filter) {
    if (filter == "")
        return -1;
    struct bpf_program fcode;
    bpf_u_int32 NetMask = 0xffffff;

    if (pcap_compile(fp, &fcode, filter.toStdString().c_str(), 1, NetMask) < 0) {
        fprintf(stderr, "\nError compiling filter: wrong syntax.\n");
        QMessageBox::warning(0, "warning", "Please input a vaild filter string\n");
        return -1;
    }

    if (pcap_setfilter(fp, &fcode) < 0) {
        fprintf(stderr, "\nError setting the filter\n");
        return -1;
    }
    return 0;
}

void CaptureThread::run() {
    pcap_t *adhandle;
    int res;
    const char *name = devicesName.at(interface_selected).c_str();
    // qDebug() << "name: " << name;
    
    if ((adhandle = pcap_open(name,                      
                              65536,                     
                              PCAP_OPENFLAG_PROMISCUOUS,
                              1000,          
                              NULL,
                              errbuf
                              )) == NULL) {
        QMessageBox::warning(0, "Warning!", "\nUnable to open the adapter. " + QString(name) + " is not supported by WinPcap\n");
        return;
    }

//    pcap_dumper_t* dumpfile = pcap_dump_open(adhandle, "Q1ngH3.txt");
//    if (dumpfile == nullptr) {
//        fprintf(stderr, "\nError opening output file\n");
//        return;
//    }

    if (pcap_datalink(adhandle) != DLT_EN10MB) {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        return;
    }

    setFilter(adhandle, Global::filter);
    int index = 1;

    while (!isStopped) {
        struct pcap_pkthdr* header = NULL;
        const u_char* data = NULL;
        res = pcap_next_ex(adhandle, &header, &data);
        if (res > 0 && header != NULL && data != NULL) {
            // printf("%d %p %d --------\n", index++, data, header->len);
            // for (int k = 0; k < 66; k++) {
            //     if (k % 16 == 0 && k != 0)
            //         printf("\n");
            //     printf("%02x ", *(data + k));
            // }
            ProtocolProcess::processPacket(header, data);
        }
        // printf("\n");
    }
    isStopped = false;
    return;
}
