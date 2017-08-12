#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>   //ifreq

#include<netinet/ip.h> // ip header
#include<netinet/udp.h> 
#include <linux/if_ether.h>






// Pseudo IP header for UDP checksum calculation
// Sizeof this pseudo_header = 88 bits (11 bytes)
struct pseudo_header
{
	uint32_t source_ip;
	uint32_t dest_ip;
	uint8_t placeholder, protocol;
	uint16_t udp_length;
};

struct ippseudo {
	struct	in_addr	ippseudo_src;	/* source internet address */
	struct	in_addr	ippseudo_dst;	/* destination internet address */
	u_char		ippseudo_pad;	/* pad, must be zero */
	u_char		ippseudo_p;	/* protocol */
	u_short		ippseudo_len;	/* protocol length */
};

///////////////////////////////////////////////////////
// DNS message: DNS header + query
// DNS Header structure
typedef struct
{
unsigned short id;       // identification number
unsigned char rd :1;     // recursion desired
unsigned char tc :1;     // truncated message
unsigned char aa :1;     // authoritive answer
unsigned char opcode :4; // purpose of message
unsigned char qr :1;     // query/response flag
unsigned char rcode :4;  // response code
unsigned char cd :1;     // checking disabled ? not sure about this
unsigned char ad :1;     // authenticated data ? not sure about this
unsigned char z :1;      // its z! reserved ? Should be 3 bits?
unsigned char ra :1;     // recursion available
unsigned short q_count;  // number of question entries
unsigned short ans_count; // number of answer entries
unsigned short auth_count; // number of authority entries
unsigned short add_count; // number of resource entries
} DNS_HEADER;

// Query structure: Not included QNAME which is variable length
typedef struct
{
unsigned short qtype;
unsigned short qclass;
} QUESTION;

// Actual/complete Query structure:
typedef struct
{
	unsigned char *name;
	QUESTION *ques;
} QUERY;
///////////////////////////////////////////////////////////////////

int parseBuffer(char * buffer, unsigned char * mac1);

// Parse and print header information
int printIPheader(struct iphdr * ipHeader);
int printUPDheader(struct udphdr *udpHeader);
int printDNSInfo(DNS_HEADER *dnsHeader, char * queryName);

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

int create_socket()
{
	// create raw UDP socket
	int s;
	if ( (s = socket(AF_PACKET, SOCK_RAW, IPPROTO_UDP)) == -1)
	{
		printf("Creating raw socket failed\n");
		return -1;
	}
	else
	{
		printf("Raw socket created\n");
	}
	
	// Create datagram consisting of IP header, UDP header, and data
	char datagram[4096];
	memset(datagram, 0, sizeof(datagram));
	
	// IP header defined in netinet/ip.h
	struct iphdr *ipheader = (struct iphdr *)datagram;
	
	// UDP headerip
	struct udphdr * udpheader = (struct udphdr *) (datagram + sizeof(struct iphdr));
	
	// Actual data
	char *data;
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data, "xyxxiiehgiehgiez");
	
	
	//IP header part
	// Create a socket address for setting IP header
	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(9997);
	sin.sin_addr.s_addr = inet_addr("1.2.3.4");
	
	char source_ip[] = "192.168.1.159";

	// Fill IP header
	ipheader->ihl = 5;
	ipheader->version = 4;
	ipheader->tos = 0;
	ipheader->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data);
	ipheader->id = htonl(54321); // id of this packet
	ipheader->frag_off = 0;
	ipheader->ttl = 255;
	ipheader->protocol =IPPROTO_UDP; 
	ipheader->check = 0; // Need to set it to actual checksum after calculation
	ipheader->saddr = inet_addr(source_ip); // Need to set to dns server ip	
	ipheader->daddr = sin.sin_addr.s_addr;
	
	// Calculate checksum now
	// ipheader->check = calc_checksum( (unsigned short *)datagram, ipheader->tot_len );

	// Items in UDP header
	uint16_t source_port = 9997, dest_port;
	uint16_t udp_header_len, udp_checksum;
	
	udpheader->source = htons(9997);
	udpheader->dest = htons(12345);
	udpheader->len = htons(8); // UDP header len = 8 bytes
	udpheader->check = 0; // set to 0 for checksum calculation

	
	
	// Pseudo IP header calculation for UDP
	struct pseudo_header * pheader;
	pheader = (struct pseudo_header*) malloc(sizeof(struct pseudo_header));
	printf("source_ip: %s\n", source_ip);
	struct in_addr temp_addr;
	inet_aton(source_ip, &(temp_addr));
	pheader->source_ip = temp_addr.s_addr;
	pheader->dest_ip = sin.sin_addr.s_addr;
	pheader->placeholder = 0;
	pheader->protocol = IPPROTO_UDP;
	pheader->udp_length = htons(sizeof(struct udphdr) + strlen(data));

	// temporary variable to store the sizeof pheader
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
	char *pseudo_datagram = (char *)malloc(psize);
	
	memcpy(pseudo_datagram, (char *)pheader, sizeof(struct pseudo_header));
	memcpy(pseudo_datagram + sizeof(struct pseudo_header), udpheader, sizeof(struct udphdr));
	
	udpheader->check = calc_checksum( (unsigned short*) pseudo_datagram, psize);
	
	// Now setsockopt to inform kernel that IP headers are also included
	int one = 1;
	const int * val = &one;
	errno = 0;
	if ( setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0 )
	{
		printf("setsockopt failed\n");
		fprintf(stderr, "error: %s\n", strerror(errno));
		return -1;
	}
	printf("Entering while loop\n");
	while (1)
	{
		printf("sending packet\n");
		if ( sendto(s, datagram, ipheader->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		{
			printf("sendto failed\n");
			return -1;
		}
		else
		{
			printf("Sent UDP packet, length: %d\n", ipheader->tot_len);
		}
		usleep(1000*1000);
	}
	

	free(pseudo_datagram);
	free(pheader);
}


int receiveData()
{
	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(53);
	//sin.sin_addr.s_addr = inet_addr("192.168.2.249");
	sin.sin_addr.s_addr = inet_addr("127.0.0.1");
	//sin.sin_addr.s_addr = htonl(IN_ADDR_ANY);

	int s;
	if ( (s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	//if ( (s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		printf("socket creation failed\n");
		return -1;
	}

	char buffer[4096] = {0};

	int len;
	int sizeSocket = sizeof(sin);
	// Need to bind the socket to the sockaddr_in sin
	if (bind(s, (sockaddr *)&sin, (socklen_t )sizeSocket) < 0)
	{
		printf("Can't bind\n");
		return -1;
	}
	while (1)
	{
		printf("Listening----------\n----------\n");
		if ( (len = recvfrom(s, buffer, sizeof(buffer), 0, 
			(sockaddr *)&sin, (socklen_t* )&sizeSocket)) == -1 )
		{
			printf("receive failed\n");
			return -1;
		}
	}

}

int receiveDataRaw(unsigned char * mac1)
{
	sockaddr_in sin;
	memset((void*)&sin, 0, sizeof(sin));
	//sin.sin_family = AF_INET;
	///sin.sin_addr.s_addr = inet_addr("197.9.0.1");	
	//sin.sin_port = htons(7772); 
	int s;
	//sin.sin_addr.s_addr = htonl(IN_ADDR_ANY); 	
	if ( (s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
	{
		printf("socket creation failed\n");
		fprintf(stderr,"%s", strerror(errno)); 
		return -1;
	}

	char buffer[65536] = {0};

	int len;
	int sizeSocket = sizeof(sin);

	while (1)
	{
		// printf("Listening----------\n----------\n");
		if ( (len = recvfrom(s, buffer, sizeof(buffer), 0, 
			(sockaddr *)&sin, (socklen_t* )&sizeSocket)) == -1 )
		{
			printf("receive failed\n");
			return -1;
		}
		else
		{
			parseBuffer(buffer, mac1);
			// printf("Len %d bytes received\n", len);
		}

// printMAC:
// 		printf("Source MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X, %d, %d\n", eHeader->h_source[0], 
// 				eHeader->h_source[1], eHeader->h_source[2], eHeader->h_source[3],
// 				eHeader->h_source[4], eHeader->h_source[5], (unsigned char) eHeader->h_source[4], (unsigned char)eHeader->h_source[5]);
// 		printf("Destination MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X, %d, %d\n", eHeader->h_dest[0], 
// 				eHeader->h_dest[1], eHeader->h_dest[2], eHeader->h_dest[3], 	
// 				eHeader->h_dest[4], eHeader->h_dest[5], (unsigned char)eHeader->h_dest[0], (unsigned char)eHeader->h_dest[1]);

	}

}

int parseBuffer(char * buffer, unsigned char * mac1)
{
	// ethhdr
	struct ethhdr * eHeader = (struct ethhdr *)buffer;

	if ( !memcmp((const void*)mac1, (const void*)eHeader->h_source, ETH_ALEN) )
	{
		printf("MAC source matched with wlan0\n");
		// goto printMAC;
	}
	else if ( !memcmp((const void*)mac1, (const void*)eHeader->h_dest, ETH_ALEN) )
	{
		printf("MAC source matched with wlan0\n");
		// goto printMAC;
	}
	else
	{
		// printf("No match in src or dest MAC\n");
		// continue;
	}

	// iphdr
	struct iphdr * ipHeader = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	


	struct udphdr * udpHeader = (struct udphdr *) (buffer + sizeof(struct ethhdr) + sizeof(iphdr));



	if (printUPDheader(udpHeader) == 1)
	{
		DNS_HEADER * dnsHeader = (DNS_HEADER *) (buffer + sizeof(struct ethhdr) + sizeof(iphdr)
								+ sizeof(struct udphdr));
		char *queryName = (char *) (buffer + sizeof(struct ethhdr) + sizeof(iphdr)
								+ sizeof(struct udphdr) + sizeof(DNS_HEADER));

		printIPheader(ipHeader);
		printDNSInfo(dnsHeader, queryName);
	}


}



int printDNSInfo(DNS_HEADER *dnsHeader, char * queryName)
{
	printf("dnsHeader->q_count: %d\n", ntohs(dnsHeader->q_count));
	// printf("dnsHeader->dest: %d\n", ntohs(udpHeader->dest));
	// printf("dnsHeader->len: %d\n", ntohs(udpHeader->len));
	// printf("dnsHeader->check: %d\n", ntohs(udpHeader->check));
	printf("queryName: %s\n", queryName);

	return 0;
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

int printIPheader(struct iphdr * ipHeader)
{
	printf("ip: \n");
	// printf("ipHeader->ihl: %d\n", ipHeader->ihl);
	// printf("ipHeader->version: %d\n", ipHeader->version);
	// printf("ipHeader->tos: %d\n", ipHeader->tos);
	// printf("ipHeader->tot_len: %d\n", ipHeader->tot_len);
	// printf("ipHeader->id: %d\n", ipHeader->id);
	// printf("ipHeader->frag_off: %d\n", ipHeader->frag_off);
	// printf("ipHeader->ttl: %d\n", ipHeader->ttl);
	// printf("ipHeader->protocol: %d\n", ipHeader->protocol);
	printf("ipHeader->check: %d\n", ipHeader->check);

	struct in_addr temp_src, temp_dest;
	temp_src.s_addr = ipHeader->saddr;
	temp_dest.s_addr = ipHeader->daddr;
	printf("ipHeader->srcIP: %s\n", inet_ntoa(temp_src));
	printf("ipHeader->destIP: %s\n", inet_ntoa(temp_dest));

	return 0;
}

int main()
{
	// Get mac addr first 
	unsigned char intf_mac[ETH_ALEN] = {0};
	const char intf[] = "wlan0";
	getMAC(intf, intf_mac);
	printf("%s, MAC: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", intf, intf_mac[0], intf_mac[1], intf_mac[2],
		intf_mac[3], intf_mac[4], intf_mac[5]);
	//create_socket();
	 //receiveData();
	 receiveDataRaw(intf_mac);

	return 0;
}
