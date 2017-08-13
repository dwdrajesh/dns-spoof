#include "udpHandler.h"

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int createSpoofUDPhdr(struct udphdr *udpHeader, struct udphdr *spoofUDPHeader, unsigned int dns_length)
{
	spoofUDPHeader->source = udpHeader->dest;
	spoofUDPHeader->dest = udpHeader->source;
	spoofUDPHeader->len = sizeof(udphdr) + dns_length;
	spoofUDPHeader->check = 0;
}



int printUPDheader(struct udphdr *udpHeader)
{
	if ( (ntohs(udpHeader->dest) == 53) || (ntohs(udpHeader->dest) == 53) )
	{
		printf("udpHeader->source: %d\n", ntohs(udpHeader->source));
		printf("udpHeader->dest: %d\n", ntohs(udpHeader->dest));
		printf("udpHeader->len: %d\n", ntohs(udpHeader->len));
		// printf("udpHeader->check: %d\n", ntohs(udpHeader->check));

		return 1;
	}

	return 0;
}


