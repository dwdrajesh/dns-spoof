#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>



// Header structure
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

// Resource Record structure: We have not included the name and RDATA which are variable length



// Actual/complete Query structure:
typedef struct
{
	unsigned char *name;
	QUESTION *ques;
} QUERY;

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


void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

u_char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        // for(j=0;j<p - '0';j++)  // can we use p - '0' ? 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    // name[i-1]='\0'; //remove the last dot
    name[i-1]='\0'; //remove the last dot // i -2 or -1
    return name;
}




int main()
{
	// Create UDP socket to send DNS query
	int sockfd;
	if ( (sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
	{
		printf("Error in socket creation\n");
		return -1;
	}

	sockaddr_in destination_addr;
	destination_addr.sin_family = AF_INET;
	destination_addr.sin_port = htons(53);
	destination_addr.sin_addr.s_addr = inet_addr("127.0.1.1");

	unsigned char buffer[65535] = {0};

	DNS_HEADER *header = (DNS_HEADER *) &buffer;

	header->id = (unsigned short) htons(getpid());
	header->rd = 1; // recursion desired
	header->tc = 0; // no truncation
	header->aa = 0; // authoritative answer, for response only
	header->opcode = 0; // 0 = standard query
	header->qr = 0; // qr is 1 for response only

	header->ra = 0; // no recursion available
	header->z = 0 ; // z is 0
	header->ad = 0; // z is supposed to be 3 bits but we take only 1 bit for z and 
	// rest two for 'ad' and 'cd'	
	header->cd = 0;
	header->rcode = 0; // response code, 0 in queries
	header->q_count = htons(1); // no. of questions
	header->ans_count = 0; // 0 for queries
	header->auth_count = 0;
	header->add_count = 0;


	// QUERY = name + QUESTION (qtype + qclass)
	// QUERY struct for the query part of the DNS message
	QUERY * query = NULL; // not using the QUERY class for now, using name and question separately
	// point qname to after the header
	unsigned char *qname;
	qname = (unsigned char*)&buffer[sizeof(DNS_HEADER)];
	unsigned char temphostname[] = "www.stanford.edu";
	// unsigned char temphostname[] = "www.google.com";
	ChangetoDnsNameFormat(qname , temphostname);

	printf("qname is: %s\n", qname);
	unsigned short tempval = htons(0xffff);
	// qname = (unsigned char*)&tempval; // In DNS format
	// qname = temphostname;

	printf("len of qname: %d\n", (int)strlen((const char*)qname));
	QUESTION * question = (QUESTION *)&buffer[sizeof(DNS_HEADER) + (strlen((const char *)qname) + 1)];

	question->qtype = htons(0x0001); // requesting ipv4 address
	question->qclass = htons(0x0001); // internet means 1 for class


	// Now send the DNS message over the UDP socket created earlier
	if (sendto(sockfd, (char *)buffer, sizeof(DNS_HEADER) + 
		(strlen((const char *)qname) + 1) + sizeof(QUESTION), 0, (sockaddr *)&destination_addr,
		sizeof(destination_addr)) == -1)
	{
		printf("sendto failed...\n");
		return -1;
	}

	int sock_len = sizeof(destination_addr);
	if ( int bytes = recvfrom(sockfd, (char *)buffer, 65536, 0, (sockaddr *)&destination_addr, 
		(socklen_t *)&sock_len) < 0 )
	{
		printf("recvfrom failed...\n");
	}
	else
	{
		printf("bytes received: %d\n", bytes);
	}

	DNS_HEADER * received_header = (DNS_HEADER *) &buffer;
	printf("The received message has: %d questions\n", ntohs(received_header->q_count));
	printf("The received message has: %d answers\n", ntohs(received_header->ans_count));
	printf("The received message has: %d authoritative servers\n", ntohs(received_header->auth_count));
	printf("The received message has: %d additional records\n", ntohs(received_header->add_count));

	// Set buffer to after the DNS header and question part for answers
	unsigned char * read_buffer;
	read_buffer = &buffer[sizeof(DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(QUESTION)];


	RES_RECORD answers[20], auth[20], addit[20]; // Take array for 20 answers for now



	int stop = 0; // To denote offset? (not sure)
	for (int i = 0; i < ntohs(received_header->ans_count); i++)
	{
		// name is the first entry in RES_RECORD structure
		answers[i].name = ReadName(read_buffer, buffer, &stop);
		printf("answers[i].name: %s\n", answers[i].name);

		// add offset for name to read other items in the RES_RECORD struct
		read_buffer = read_buffer + stop;
		answers[i].resource = (RR_CONSTANT_FIELD *)read_buffer;

		// add offset for the struct RR_CONSTANT_FIELD
		read_buffer = read_buffer + sizeof(RR_CONSTANT_FIELD);

		// Next item is r_data char buffer
		// But need to know the length of r_data
		if (ntohs(answers[i].resource->type) == 1) // ipv4 is 1
		{
			// malloc for r_data
			answers[i].rdata = (unsigned char *)malloc(ntohs(answers[i].resource->data_len));
			// try memcpy for now?		answers[i].r_data[i]
			memcpy(answers[i].rdata, read_buffer, sizeof(answers[i].rdata));
			
			// answers[i].rdata[ntohs(answers[i].resource->data_len) - 1] = '\0';
			// no need for - 1 as memcpy is done for strlen, which doesn't take the last \0 byte.
			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0'; 
			// move forward the read_buffer
			read_buffer = read_buffer + ntohs(answers[i].resource->data_len);
		}
		else
		{
			// ipv6 not handled now?
			printf("resource type not 1, is: %d\n", ntohs(answers[i].resource->type));
			// just read the buffer 
			answers[i].rdata = ReadName(read_buffer, buffer, &stop);
			read_buffer = read_buffer + stop;
		}
		unsigned long ip_int = *(unsigned long *)answers[i].rdata;
		char ip_str[64] = {0};
		struct sockaddr_in temp_addr;
		temp_addr.sin_addr.s_addr = ip_int;
		inet_ntop(AF_INET, &(temp_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
		printf("answers[i].name: %s, ip returned is: %s\n", answers[i].name,ip_str);


	}

	return 0;
}