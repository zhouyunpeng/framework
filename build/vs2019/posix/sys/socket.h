#pragma once
//#include <winsock.h>
//#include <ws2ipdef.h>
#include <WinSock2.h>
#include <ws2ipdef.h>
#include <WS2tcpip.h>

//typedef struct in_addr {
//        union {
//                struct { unsigned char s_b1,s_b2,s_b3,s_b4; } S_un_b;
//                struct { unsigned short s_w1,s_w2; } S_un_w;
//                unsigned long S_addr;
//        } S_un;
//#define s_addr  S_un.S_addr /* can be used for most tcp & ip code */
//#define s_host  S_un.S_un_b.s_b2    // host on imp
//#define s_net   S_un.S_un_b.s_b1    // network
//#define s_imp   S_un.S_un_w.s_w2    // imp
//#define s_impno S_un.S_un_b.s_b4    // imp #
//#define s_lh    S_un.S_un_b.s_b3    // logical host
//} IN_ADDR, *PIN_ADDR, *LPIN_ADDR;
//
//struct sockaddr_in {
//        short   sin_family;
//        unsigned short sin_port;
//        struct  in_addr sin_addr;
//        char    sin_zero[8];
//};

#define AF_INET         2               /* internetwork: UDP, TCP, etc. */
#define AF_INET6        23              // Internetwork Version 6

#define SOCK_STREAM     1               /* stream socket */
//#define close closesocket
