#include "ipHandler.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

unsigned short calc_checksum(unsigned short *datagram, unsigned int tot_len)
{
	unsigned long sum;
	// Add over 16 bits (unsigned short)
	for (sum = 0; tot_len > 0; tot_len--)
	{
		sum += *datagram++;		
	}
	// Add remaining last 8 bits now
	//if (datagram)
	//{
	//	sum += datagram;
	//}
	
	// Add carry now
	sum = sum >> 16 + (sum & 0xffff);
	sum += sum >> 16;
	
	return (unsigned short)(~sum);
}



int getIPinfo(char * buffer, unsigned long * ipsrc, unsigned long * ipdest)
{
	struct iphdr * ipHeader = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	*ipsrc = ipHeader->saddr;
	*ipdest = ipHeader->daddr;

	return 0;
}

int createSpoofIPhdr(char * newBuffer, struct iphdr *ipHeader, struct iphdr *spoofIPHeader, unsigned int dns_length)
{
	// memcpy last arg is bytes (not bits)
	//memcpy(spoofIPHeader->ihl, ipHeader->ihl, 1);
	spoofIPHeader->ihl = ipHeader->ihl;
	spoofIPHeader->version = ipHeader->version;
	spoofIPHeader->tos =  ipHeader->tos;
	// tot_len is gonna be the size of iphdr struct finally with checksum included
	spoofIPHeader->tot_len= sizeof(struct iphdr) + sizeof(struct udphdr) 
				+ dns_length;; // This field needs to be modified

	spoofIPHeader->id = ipHeader->id; // This field needs to be modified
	spoofIPHeader->frag_off = 0; // This field needs to be modified
	spoofIPHeader->ttl =  ipHeader->ttl; 
	spoofIPHeader->protocol = ipHeader->protocol; 
	// THE most imp thing to modify
	spoofIPHeader->check = 0;
	spoofIPHeader->saddr = ipHeader->daddr;
	spoofIPHeader->daddr = ipHeader->saddr;

	ipHeader->check = calc_checksum((unsigned short*) newBuffer, sizeof(iphdr) + sizeof(udphdr) + dns_length);

	return 0;
}


int printIPheader(struct iphdr * ipHeader)
{
	printf("ip: \n");
	 printf("ipHeader->ihl: %d\n", ipHeader->ihl);
	 printf("ipHeader->version: %d\n", ipHeader->version);
	 printf("ipHeader->tos: %d\n", ipHeader->tos);
	 printf("ipHeader->tot_len: %d\n", ipHeader->tot_len);
	 printf("ipHeader->id: %d\n", ipHeader->id);
	 printf("ipHeader->frag_off: %d\n", ipHeader->frag_off);
	 printf("ipHeader->ttl: %d\n", ipHeader->ttl);
	 printf("ipHeader->protocol: %d\n", ipHeader->protocol);
	printf("ipHeader->check: %d\n", ipHeader->check);

	struct in_addr temp_src, temp_dest;
	temp_src.s_addr = ipHeader->saddr;
	temp_dest.s_addr = ipHeader->daddr;
	printf("ipHeader->srcIP: %s\n", inet_ntoa(temp_src));
	printf("ipHeader->destIP: %s\n", inet_ntoa(temp_dest));

	return 0;
}
