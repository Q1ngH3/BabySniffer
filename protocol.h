#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <winsock2.h>
#include <pcap.h>
// #include <WinSock2.h>

/* ethernet headers are always 14 bytes [1] */
#define SIZE_ETHERNET 14

/* 6字节的MAC地址 */
typedef struct mac_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
} mac_address;

typedef struct ethhdr
{
    u_char dest[6]; //6个字节 目标地址
    u_char src[6];  //6个字节 源地址
    u_short type;   //2个字节 类型
    //#define IP 0x0800
    //#define ARP 0x0806
} ethhdr;

/* 4 bytes IP address */
typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;

/*ARP首部*/
typedef struct arphdr
{
    u_short hardware_type;       // 硬件类型 (16 bits)
    u_short protocal_type;       //协议类型(16 bits)
    u_char hwadd_len;            //硬件地址长度(8 bit)
    u_char proadd_len;           //协议地址长度(8 bit)
    u_short opcode;              //操作类型(16 bits)
    mac_address snether_address; // 发送端以太网地址(48 bits)
    ip_address sip_address;      //发送端IP地址(32 bits)
    mac_address dnether_address; //目的以太网地址(48 bits)
    ip_address dip_address;      // 目的IP地址（32 bits）
} arphdr;

typedef struct iphdr
{

    u_char ver_ihl;   // 版本 (4 bits) + 首部长度 (4 bits)
    u_char tos;       //TOS 服务类型
    u_short tlen;     //包总长 u_short占两个字节
    u_short id;       //标识
    u_short frag_off; //片位移
    u_char ttl;       //生存时间
    u_char proto;     //协议
    u_short check;    //校验和
    unsigned char saddr[4];
    unsigned char daddr[4];
    u_int op_pad; //选项等
} iphdr;

typedef struct igmphdr
{
    u_char igmp_type;          /* version & type of IGMP message  */
    u_char igmp_code;          /* subtype for routing msgs        */
    u_short igmp_cksum;        /* IP-style checksum               */
    struct in_addr igmp_group; /* group address being reported    */
} igmphdr;                     /*  (zero for queries)             */

/* 16 bytes IPv6 address */
typedef struct ipv6_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
    u_char byte7;
    u_char byte8;
    u_char byte9;
    u_char byte10;
    u_char byte11;
    u_char byte12;
    u_char byte13;
    u_char byte14;
    u_char byte15;
    u_char byte16;
} ipv6_address;

typedef struct ipv6hdr
{
    u_long ver_ihl;         // 版本 (4 bits) + 优先级(8 bits)+流标签(20 bits)
    u_short load_length;    // 有效负荷长度
    u_char next_header;     // 下一报头
    u_char jump_limit;      // 跳限制
    ipv6_address source_ip; //源ip地址
    ipv6_address dest_ip;   //目的ip地址
} ipv6hdr;

typedef struct tcphdr
{
    u_short sport;    //src 16
    u_short dport;    //目的端口地址 16位
    u_int seq;        //序列号 32位
    u_int ack;        //确认序列号
    u_short tcp_res;  //TCP头长(4 bits)+保留位(6 bits)+Flags(URG+ACK+PSH+RST+SYN+FIN)
    u_short windsize; //窗口大小 16位
    u_short crc;      //校验和 16位
    u_short urgp;     //紧急指针 16位
    u_int opt;        //选项
} tcphdr;

typedef struct udphdr
{
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
} udphdr;

/* ICMP header */
typedef struct icmphdr
{
    u_char icmp_t;   /*type*/
    u_char icmp_c;   /*code*/
    u_short icmp_cs; /*check sum*/
} icmphdr;

// TCP protocol
#define FTP_PORT (21)
#define TELNET_PORT (23)
#define SMTP_PORT (25)
#define HTTP_PORT (80)
#define HTTPS_PORT (443)
#define HTTP2_PORT (8080)
#define POP3_PORT (110)

// UDP protocol
#define DNS_PORT (53)
#define SNMP_PORT (161)

#include <QString>
struct AnalyseProtoType
{
    QString strEthTitle; // 数据链路层
    QString strDMac;
    QString strSMac;
    QString strType;

    QString strNetProto; // 网络层
    QString strVersion;
    QString strHeadLength;
    QString strLength;
    QString strNextProto;
    QString strSIP;
    QString strDIP;

    QString strTranProto; // 传输层:
    QString strSPort;
    QString strDPort;

    QString strAppProto; // 应用层
    QByteArray strSendInfo;

    //other data
    char timestamp[30];         //时戳
    struct pcap_pkthdr *header; //包头

    struct ethhdr *ether_header; //以太网首部
    struct iphdr *IP_header;     //IPv4首部
    struct ipv6hdr *IPv6_header;

    struct udphdr *UDP_header;   //UDP首部
    struct tcphdr *TCP_header;   //TCP首部
    struct icmphdr *ICMP_header; //ICMP首部
    struct igmphdr *IGMP_header;
    struct arphdr *ARP_header;

    void init()
    {
        strEthTitle = "Ethernet II";
        strDMac = "Destination：";
        strSMac = "Source：";
        // strType = "Type：Internet Protocol (0x0800)";
        strType = "";

        strNetProto = "";
        strVersion = "Version：IPv4";
        strHeadLength = "Header Length：";
        strLength = "Total Length：";
        strSIP = "Source：";
        strDIP = "Destination：";

        strTranProto = "";
        strSPort = "Source Port：";
        strDPort = "Destination Port：";

        strAppProto = "";
    }
};

// 捕获的数据结构
struct SnifferData
{
    QString strNum;  // 序号
    QString strTime; // 时间
    QString strSIP;  // 来源 IP 地址，格式 IP:port
    QString strDIP;  // 目标 IP 地址，格式 IP:port
    QString strSPort;
    QString strDPort;
    QString strProto;   // 使用的协议
    QString strLength;  // 数据长度
    QByteArray strData; // 原始数据
    unsigned char *pkt_data;
    AnalyseProtoType protoInfo; // 树形显示结果的数据结构
};

// IP 协议头 协议(Protocol) 字段标识含义
//      协议      协议号

#define IP_SIG (0)
#define ICMP_SIG (1)
#define IGMP_SIG (2)
#define GGP_SIG (3)
#define IP_ENCAP_SIG (4)
#define ST_SIG (5)
#define TCP_SIG (6)
#define EGP_SIG (8)
#define PUP_SIG (12)
#define UDP_SIG (17)
#define HMP_SIG (20)
#define XNS_IDP_SIG (22)
#define RDP_SIG (27)
#define TP4_SIG (29)
#define XTP_SIG (36)
#define DDP_SIG (37)
#define IDPR_CMTP_SIG (39)
#define RSPF_SIG (73)
#define VMTP_SIG (81)
#define OSPFIGP_SIG (89)
#define IPIP_SIG (94)
#define ENCAP_SIG (98)

#endif // PROTOCOL_H

/* ARP / RARP structs and definitions */
#define ARPOP_REQUEST 1 /* ARP request.  */
#define ARPOP_REPLY 2   /* ARP reply.  */
/* Some OSes have different names, or don't define these at all */
#define ARPOP_RREQUEST 3 /* RARP request.  */
#define ARPOP_RREPLY 4   /* RARP reply.  */
/*Additional parameters as per http://www.iana.org/assignments/arp-parameters*/
#define ARPOP_DRARPREQUEST 5 /* DRARP request.  */
#define ARPOP_DRARPREPLY 6   /* DRARP reply.  */
#define ARPOP_DRARPERROR 7   /* DRARP error.  */
#define ARPOP_IREQUEST 8     /* Inverse ARP (RFC 1293) request.  */
#define ARPOP_IREPLY 9       /* Inverse ARP reply.  */
#define ATMARPOP_NAK 10      /* ATMARP NAK.  */

#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_IPv6 0x86DD
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_RARP 0x8035

#define PROTO_TYPE_ICMP 1
#define PROTO_TYPE_TCP 6
#define PROTO_TYPE_UDP 17
#define PROTO_TYPE_ICMPv6 58

/*
 * Message types, including version number.
 */
#define IGMP_HOST_MEMBERSHIP_QUERY 0x11     /* membership query         */
#define IGMP_v1_HOST_MEMBERSHIP_REPORT 0x12 /* Ver. 1 membership report */
#define IGMP_DVMRP 0x13                     /* DVMRP routing message    */
#define IGMP_PIM 0x14                       /* PIMv1 message (historic) */
#define IGMP_v2_HOST_MEMBERSHIP_REPORT 0x16 /* Ver. 2 membership report */
#define IGMP_HOST_LEAVE_MESSAGE 0x17        /* Leave-group message     */
#define IGMP_MTRACE_REPLY 0x1e              /* mtrace(8) reply */
#define IGMP_MTRACE_QUERY 0x1f              /* mtrace(8) probe */
#define IGMP_v3_HOST_MEMBERSHIP_REPORT 0x22 /* Ver. 3 membership report */
