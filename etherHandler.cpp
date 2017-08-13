#include "etherHandler.h"

#include <sys/ioctl.h>
#include <net/if.h>   //ifreq
#include <netinet/ip.h>

int getMAC(const char *intf, unsigned char *macaddr)
{
	struct ifreq *ifreq_buffer;
	ifreq_buffer = (struct ifreq *)malloc(sizeof(struct ifreq));

	memset(ifreq_buffer, 0, sizeof(struct ifreq));
	ifreq_buffer->ifr_addr.sa_family = AF_INET;
	memcpy(ifreq_buffer->ifr_name, intf, IFNAMSIZ-1);

	// Create socket to send ioctl req to 
	int s;
	if ( (s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0 )
	{
		printf("Socket creation for getMAC failed\n");
		return -1;
	}
	// ioctl
	if ( (ioctl(s, SIOCGIFHWADDR, ifreq_buffer)) < 0)
	{
		printf("Can't get MAC address\n");
		return -1;
	}

	memcpy(macaddr, ifreq_buffer->ifr_hwaddr.sa_data, ETH_ALEN);
	// printf("MAC addr of intf: %s, is %s\n", intf, macaddr);

	free(ifreq_buffer);
	return 0;
}

int createSpoofEthhdr(struct ethhdr *src, struct ethhdr *spoof)
{
	memcpy(spoof->h_source, src->h_dest, ETH_ALEN);
	memcpy(spoof->h_dest, src->h_source, ETH_ALEN);
	spoof->h_proto = src->h_proto;

	return 0;
}