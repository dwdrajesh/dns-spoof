#ifndef __UDPHANDLER_H__
#define __UDPHANDLER_H__

#include <netinet/udp.h>

int createSpoofUDPhdr(struct udphdr * UDPHeader, struct udphdr *spoofUDPHeader, unsigned int dns_length);

int getSrcPort(char * buffer, unsigned short * portsrc);
int printUPDheader(struct udphdr *udpHeader);


#endif