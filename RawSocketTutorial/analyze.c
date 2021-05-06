#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/ioctl.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include	<linux/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/ip6.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<linux/tcp.h>
#include	<netinet/udp.h>
#include	"checksum.h"
#include	"print.h"
#include    <stdlib.h>

int
AnalyzeUdp(u_char *data, int size)
{
	u_char *ptr;
	u_char *option;
	int lest;
	int optionLen, len;
	struct udphdr *udph;
	//unsigned short sum;

	ptr = data;
	lest = size;

	if(lest < sizeof(struct udphdr)) {
		fprintf(stderr, "lest(%d) < sizeof(struct udphdr)\n", lest);
		return(-1);
	}
	udph = (struct udphdr *)ptr;
	ptr += sizeof(struct udphdr);
	lest -= sizeof(struct udphdr);

	
	/* Do DNS Processing here ;Add relevant checks*/
	// checking if lest size is less than dns header size or not
	if(lest < sizeof(struct dnshdr)) {
		fprintf(stderr, "lest(%d) < sizeof(struct dnshdr)\n", lest);
		return(-1);
	}

	// start of dns header
	struct dnshdr *dns = (struct dnshdr*) ptr;
	// skipping ptr to end of dns header
	ptr += sizeof(struct dnshdr);
	lest -= sizeof(struct dnshdr);
	
	printf("\n\n DNS header info: \n");

	// printing all dns header informations
	printf("ID: %d\n", ntohs(dns->id));
	printf("Recursion: %d\n", ntohs(dns->rd));
	printf("Truncated message: %d\n", ntohs(dns->tc));
	printf("Authorative answer: %d\n", ntohs(dns->aa));
	printf("OpCode: %d\n", ntohs(dns->opcode));
	printf("Query/Response flag: %d\n", ntohs(dns->qr));
	printf("Response code: %d\n", ntohs(dns->rcode));
	printf("checking disabled: %d\n", ntohs(dns->cd));
	printf("Authenticated data: %d\n", ntohs(dns->ad));
	printf("Z! reserved: %d\n", ntohs(dns->z));
	printf("Recursion available: %d\n", ntohs(dns->ra));
	printf("Number of questions : %d\n", ntohs(dns->n_q));
	printf("Number of answers: %d\n", ntohs(dns->n_a));
	printf("Number of authority entries: %d\n", ntohs(dns->n_auth));
	printf("Number of additional entries: %d\n", ntohs(dns->n_add));

	printf("\n\nDNS query hostname: ");
	

	// example 
	// rawsocket.tut is recieved as 9rawsockets3tut

	// ptr[0] is the number of characters in domain name before first dot
	int n_chars = ptr[0];

	// printf("nchars: %d\n", n_chars);
	
	// skipping the n_chars byte
	ptr++;

	// looping for all dots in hostname
	while(n_chars > 0) {
		// printing all the characters till next dot
		for(int i=0;i<n_chars;i++) {
			printf("%c", ptr[0]);
			ptr++;
		}

		// reading number of characters
		n_chars = ptr[0];
		if(n_chars <= 0) break;
		
		printf(".");
		
		//printf("nchars: %d\n", n_chars);

		// skipping the n_chars byte
		ptr++;
	}

	ptr++;
	// reading type of dns query
	uint16_t type = ntohs( *(uint16_t *)ptr );
	ptr += 2;
	printf("\nType of DNS query: %d\n\n\n", type);

	return(0);
}

/*
	Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}


struct udp_pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

struct tcp_pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

int sendUdpReply(u_char*data, int size)
{
	
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(1);
	}
	
	//Datagram to represent the packet
	char datagram[4096] , source_ip[32];
	u_char *payload , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 4096);
	memcpy(datagram,data,size);
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct iphdr));
	
	struct sockaddr_in sin;
	//struct udp_pseudo_header psh;
	
	//Data part
	payload = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(payload , "Hello message from UDP raw socket");
	
	//some address resolution
	strcpy(source_ip , "192.168.1.22");
	
	sin.sin_family = AF_INET;
	sin.sin_port = udph->source;
	sin.sin_addr.s_addr = iph->daddr;//inet_addr ("192.168.1.21");
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(payload);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	uint32_t srcIp = iph->saddr;
	iph->saddr = iph->daddr;//inet_addr (source_ip );	
	iph->daddr = srcIp;//sin.sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
	//UDP header
	int srcPort = udph->source;
	udph->source = udph->dest;
	udph->dest = srcPort;
	udph->len = htons(8 + strlen(payload));	
	udph->check = 0;	
	char dstAddr[100];
    ip_ip2str(iph->daddr, dstAddr, sizeof(dstAddr));
	printf("sending UDP Packet to %s of size %d\n", dstAddr,iph->tot_len);
	#if 0
	//Now the UDP checksum using the pseudo header
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(payload) );
	
	int psize = sizeof(struct udp_pseudo_header) + sizeof(struct udphdr) + strlen(payload);
    int bytes;
    socklen_t sinSize = sizeof(struct sockaddr_in);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct udp_pseudo_header));
	memcpy(pseudogram + sizeof(struct udp_pseudo_header) , udph , sizeof(struct udphdr) + strlen(payload));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);
	#endif
//	//Send the packet
	if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
	}
	//Data send successfully
	else
	{
		printf ("Packet Sent of length : %d \n" , iph->tot_len);
	}
	return 0;
}



int sendTcpReply(u_char *data, int size)
{
	//Create a raw socket of type IPPROTO
	int s = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);

	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(1);
	}
	
	char source_ip[32];
	char streamdata[4096];
	u_char *payload , *pseudogram;
	
	//zero out the packet buffer
	memset (streamdata, 0, 4096);
	memcpy(streamdata,data,size);
	//IP header
	struct iphdr *iph = (struct iphdr *) streamdata;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (streamdata + sizeof (struct ip));
	
	struct sockaddr_in sin;
	struct tcp_pseudo_header psh;
	#if 1
	//Data part
	payload = streamdata + sizeof(struct iphdr) + sizeof(struct tcphdr);
	strcpy(payload , "Hello from TCP Raw Server");
	#endif
	//some address resolution
	strcpy(source_ip , "192.168.1.22");
	
	sin.sin_family = AF_INET;
	sin.sin_port = tcph->source;
	sin.sin_addr.s_addr = inet_addr ("192.168.1.21");
	
	iph->saddr = inet_addr ( source_ip );	
	iph->daddr = sin.sin_addr.s_addr;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + strlen(payload);
	printf("Total length so far %d", iph->tot_len);
	//Ip checksum
	iph->check = csum ((unsigned short *) streamdata, iph->tot_len);
	
	#if 1
	//TCP Header
	int srcPort = tcph->source;
	tcph->source = tcph->dest;
	tcph->dest = srcPort;
	tcph->seq = 0;
	tcph->ack_seq = 1;
	tcph->doff = 5;	//tcp header size
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=1;
	tcph->urg=0;
	tcph->ece=0;
	tcph->cwr=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	tcph->urg_ptr = 0;
	
	//Now the TCP checksum
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(payload) );
	
	int psize = sizeof(struct tcp_pseudo_header) + sizeof(struct tcphdr) + strlen(payload);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct tcp_pseudo_header));
	memcpy(pseudogram + sizeof(struct tcp_pseudo_header) , tcph , sizeof(struct tcphdr) + strlen(payload));
	
	tcph->check = csum( (unsigned short*) pseudogram , psize);
	
	#endif
	
	//	//Send the packet
	if (sendto (s, streamdata, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
		perror("sendto failed");
	}
	//Data sent successfully
	else
	{
		printf ("Packet Sent of length : %d \n" , iph->tot_len);
	}
	return 0;
}

void print_ip(unsigned int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

int
AnalyzeIp(u_char *data, int size)
{
	u_char *ptr;
	u_char *option;
	int lest;
	int optionLen;
	struct iphdr *iphdr;
	int ret = 0;

	ptr = data;
	lest = size;

	if(lest < sizeof(struct iphdr)) {
		fprintf(stderr, "lest(%d) < sizeof(struct iphdr)\n", lest);
		return(-1);
	}
	iphdr = (struct iphdr *)ptr;
	ptr += sizeof(struct iphdr);
	lest -= sizeof(struct iphdr);

	optionLen = iphdr->ihl * 4 - sizeof(struct iphdr);
	if(optionLen > 0) {
		if(optionLen>=1500) {
			fprintf(stderr, "IP optionLen(%d):too big\n",
				optionLen);
			return(-1);
		}
		option = ptr;
		ptr += optionLen;
		lest -= optionLen;
	}

	if(checkIPchecksum(iphdr, option, optionLen) == 0) {
		fprintf(stderr, "bad ip checksum\n");
		return(-1);
	}

        char srcAddr[100];
        ip_ip2str(iphdr->saddr, srcAddr, sizeof(srcAddr));
        //printf("Received IP Packet from %s\n", srcAddr);
  		  struct tcphdr *tcph = (struct tcphdr *) (data + sizeof (struct iphdr));

        if(!strcmp(srcAddr,"192.168.1.21") && iphdr->protocol==6) // TCP with specific IP Address
        {
           printf("Received a TCP packet from intended client\n");
            // Send response only if SYN
			  if(tcph && tcph->syn == 1) {
            
              iphdr->saddr = htonl(0xc0a80116);//192.168.1.22
              iphdr->daddr = htonl(0xc0a80115);//192.168.1.21
              char dstAddr[100];
              ip_ip2str(iphdr->daddr, dstAddr, sizeof(dstAddr));
              printf("sending IP Packet to %s\n", dstAddr);
		        sendTcpReply(data, size);
			  }
           ret = 0;
        } 
       else if (!strcmp(srcAddr,"192.168.1.21") && iphdr->protocol==17) // UDP with specific IP Address)
       {
			printf("Received a UDP packet from intended client\n");
#if 0
		    iphdr->saddr = htonl(0xc0a80116);//192.168.1.22
          iphdr->daddr = htonl(0xc0a80115);//192.168.1.21
			
          char dstAddr[100];
          ip_ip2str(iphdr->daddr, dstAddr, sizeof(dstAddr));
          printf("sending UDP Packet to %s of size %d\n", dstAddr,ntohs(iphdr->tot_len));
#endif
            
			sendUdpReply(data,size);
			ret = 0;//1;
       }
    	else
        	return(0);

	PrintIpHeader(iphdr, option, optionLen, stdout);

	/* If you want to show the next header, TCP, UDP, ICMP, etc., */
	/* call your protocol-specific analyzer here!!                */
	if(iphdr->protocol==17) /* If UDP Packet */
	{
		printf("Received a UDP packet \n");
		AnalyzeUdp(ptr, lest);
		//udph = (struct iphdr *)ptr;
		PrintUdpHeader((struct udphdr *)ptr, stdout);
		// returning 1 if dns udp packet is received
		// so as to terminate the raw socket
		return 1;
	}
	
	return ret;
}


int
AnalyzePacket(u_char *data, int size)
{
	u_char *ptr;
	int lest, ret=0;
	struct ether_header *eh;

	ptr = data;
	lest = size;

	if(lest < sizeof(struct ether_header)) {
		fprintf(stderr, "lest(%d) < sizeof(struct ether_header)\n", lest);
		return(-1);
	}
	eh = (struct ether_header *)ptr;
	ptr += sizeof(struct ether_header);
	lest -= sizeof(struct ether_header);

	
	printf("\n\n");

	if(ntohs(eh->ether_type) == ETHERTYPE_ARP) {
		fprintf(stderr, "Packet[%dbytes]\n", size);
		PrintEtherHeader(eh, stdout);
	}
	else if(ntohs(eh->ether_type) == ETHERTYPE_IP) {
		fprintf(stderr, "Packet[%dbytes]\n", size);
	//	PrintEtherHeader(eh, stdout);
		ret = AnalyzeIp(ptr, lest);
	}

	return(ret);
}
