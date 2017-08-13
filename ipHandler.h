#ifndef __IPHANDLER_H__
#define __IPHANDLER_H__

#include <netinet/ip.h>
#include <netinet/udp.h>
#include "etherHandler.h"

int printIPheader(struct iphdr * ipHeader);
int getIPinfo(char * buffer, unsigned long * ipsrc, unsigned long * ipdest);
unsigned short calc_checksum(unsigned short *datagram, unsigned int tot_len);

int createSpoofIPhdr(char * newBuffer, struct iphdr *ipHeader, struct iphdr *spoofIPHeader, unsigned int dns_length);

#endif