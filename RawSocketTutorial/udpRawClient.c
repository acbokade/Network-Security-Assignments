
/*
	Raw UDP sockets
*/
#include<stdio.h>	//for printf
#include<string.h> //memset
#include<sys/socket.h>	//for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<linux/udp.h>	//Provides declarations for udp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include	<arpa/inet.h>
#include	<unistd.h>
#include	<netinet/if_ether.h>
#define ADDR_TO_BIND "192.168.1.21"
#define PORT_TO_BIND 6666 //9090
/* 
	96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t udp_length;
};

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

int main (void)
{
	//Create a raw socket of type IPPROTO
	int s = socket (PF_INET, SOCK_RAW, IPPROTO_RAW);
//	int s = socket (AF_INET, SOCK_RAW, IPPROTO_UDP);
	
	if(s == -1)
	{
		//socket creation failed, may be because of non-root privileges
		perror("Failed to create raw socket");
		exit(1);
	}
	
	//Datagram to represent the packet
	char datagram[4096] , source_ip[32] , *data , *pseudogram;
	
	//zero out the packet buffer
	memset (datagram, 0, 4096);
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//UDP header
	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
	
	struct sockaddr_in sin;
	struct pseudo_header psh;
	
	//Data part
	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
	strcpy(data , "Hello from UDP Raw client");
	
	//some address resolution
	strcpy(source_ip , "192.168.1.21");
	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(7000);
	sin.sin_addr.s_addr = inet_addr ("192.168.1.22");
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
	iph->id = htonl (54321);	//Id of this packet
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->check = 0;		//Set to 0 before calculating checksum
	iph->saddr = inet_addr ( source_ip );	
	iph->daddr = sin.sin_addr.s_addr;
	
	//Ip checksum
	iph->check = csum ((unsigned short *) datagram, iph->tot_len);
	
	//UDP header
	udph->source = htons (6666);
	udph->dest = htons (7000);
	udph->len = htons(8 + strlen(data));	//tcp header size
	udph->check = 0;	//leave checksum 0 now, filled later by pseudo header
	
	//Now the UDP checksum using the pseudo header
	psh.source_address = inet_addr( source_ip );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );
	
	int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + strlen(data);
        int bytes;
socklen_t sinSize = sizeof(struct sockaddr_in);
	pseudogram = malloc(psize);
	
	memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header) , udph , sizeof(struct udphdr) + strlen(data));
	
	udph->check = csum( (unsigned short*) pseudogram , psize);
	
//	while (1)
//	{
		//Send the packet
		if (sendto (s, datagram, iph->tot_len ,	0, (struct sockaddr *) &sin, sizeof (sin)) < 0)
		{
			perror("sendto failed");
		}
		//Data send successfully
		else
		{
			printf ("Packet Sent of length : %d \n" , iph->tot_len);
		}
//	       int rd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
//	int rd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	int rd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
//                int bytes = recvfrom(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, &sinSize);
#if 1
    struct sockaddr_in sockstr;
    socklen_t socklen;
    sockstr.sin_family = AF_INET;
    sockstr.sin_port = htons(PORT_TO_BIND);
    sockstr.sin_addr.s_addr = inet_addr(ADDR_TO_BIND);
    socklen = (socklen_t) sizeof(sockstr);

    /* use socklen instead sizeof()  Why had you defined socklen? :-)  */
    if (bind(rd, (struct sockaddr*) &sockstr, socklen) == -1) {
        perror("bind");
        exit(1);
    }
#endif
	while (1)
        {
           //int bytes = read(rd, datagram, sizeof(datagram));
           int bytes = recv(rd, datagram, sizeof(datagram),0);

	//IP header
//	struct udphdr *udph = (struct udphdr *) (datagram + sizeof (struct ip));
//	iph = (struct iphdr*) (datagram + sizeof(struct ether_header));
	iph = (struct iphdr *) datagram;
	
//         if(iph && iph->saddr == 0x922ba8c0)
            printf ("Packet received. Length : %d : %d, %x: %x %d\n" , bytes, iph->tot_len, iph->daddr, iph->saddr, iph->protocol);
	}
	
	return 0;
}

//Complete
