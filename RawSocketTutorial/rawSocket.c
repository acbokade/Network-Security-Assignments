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
#include	"analyze.h"

int
InitRawSocket(char *device)
{
	struct ifreq ifreq;
//	struct sockaddr_ll sa;
	int s;

	//if((s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
	if((s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
	//if((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("socket");
		return(-1);
	}

	/* GET the index of corresponding NIC name */
	memset(&ifreq, 0, sizeof(struct ifreq));
	strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
	if(ioctl(s, SIOCGIFINDEX, &ifreq) < 0) {
		perror("ioctl");
		close(s);
		return(-1);
	}

#if 0
	/* Set the property of NIC for packet captureing */
	sa.sll_family = AF_PACKET;
	sa.sll_protocol = htons(ETH_P_IP);
//	sa.sll_protocol = IPPROTO_RAW;
	sa.sll_ifindex = ifreq.ifr_ifindex;
	if(bind(s, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("bind");
		close(s);
		return(-1);
	}
#endif

	/* GET the flags set on NIC */
	if(ioctl(s, SIOCGIFFLAGS, &ifreq) < 0) {
		perror("ioctl");
		close(s);
		return(-1);
	}

	/* SET the PROMISCUOUS MODE flags to NIC */
	ifreq.ifr_flags = ifreq.ifr_flags|IFF_PROMISC;
	if(ioctl(s, SIOCSIFFLAGS, &ifreq) < 0) {
		perror("ioctl");
		close(s);
		return(-1);
	}

//#endif
	return(s);
}


int
main(int argc, char *argv[], char *envp[])
{
	int	s, len, ret=0;	
	u_char	buf[65535];

	if(argc <= 1) {
		fprintf(stderr, "pcap device-name\n");
		return(1);
	}

	if((s = InitRawSocket(argv[1])) == -1) {
		fprintf(stderr, "InitRawSocket:error:%s\n", argv[1]);
		return(-1);
	}

	while(1) {
		if((len = read(s ,buf, sizeof(buf))) <= 0){
			perror("read");
		}
		else{
			printf("\nLength of packet = %d\n", len);
		    ret = AnalyzePacket(buf, len);
			printf("%d\n", ret);
			printf("\nReceived return %d from analysis\n", ret);  
			if(ret) {
				if((len = write(s ,buf, sizeof(buf))) <= 0){
					perror("write");
				}
				break;
			}           
		}
	}

	close(s);

	return(0);
}
