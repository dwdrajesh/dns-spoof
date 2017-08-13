#ifndef __ETHERHANDLER_H__
#define __ETHERHANDLER_H__

#include <linux/if_ether.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

int getMAC(const char *intf, unsigned char *macaddr);
int createSpoofEthhdr(struct ethhdr *eHeader, struct ethhdr * spoofethHeader);

#endif