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
#include	<netinet/tcp.h>
#include	<netinet/udp.h>

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

char *
my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
	snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x",
		hwaddr[0], hwaddr[1], hwaddr[2],
		hwaddr[3], hwaddr[4], hwaddr[5]);

	return(buf);
}

char *
arp_ip2str(u_int8_t *ip, char *buf, socklen_t size)
{
	snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);

	return(buf);
}

char *
ip_ip2str(u_int32_t ip, char *buf, socklen_t size)
{
	struct in_addr *addr;

	addr = (struct in_addr *)&ip;
	inet_ntop(AF_INET, addr, buf, size);

	return(buf);
}

int
PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
	char	buf[80];

	fprintf(fp, "ether_header----------------------------\n");
	fprintf(fp, "ether_dhost=%s\n",
		my_ether_ntoa_r(eh->ether_dhost,buf, sizeof(buf)));
	fprintf(fp, "ether_shost=%s\n",
		my_ether_ntoa_r(eh->ether_shost,buf,sizeof(buf)));
	fprintf(fp, "ether_type=%02X", ntohs(eh->ether_type));
	switch(ntohs(eh->ether_type)){
		case	ETH_P_IP:
			fprintf(fp, "(IP)\n");
			break;
		case	ETH_P_IPV6:
			fprintf(fp, "(IPv6)\n");
			break;
		case	ETH_P_ARP:
			fprintf(fp, "(ARP)\n");
			break;
		default:
			fprintf(fp, "(unknown)\n");
			break;
	}

	return(0);
}

static char *Proto[] = {
        "undefined",
        "ICMP",
        "IGMP",
        "undefined",
        "IPIP",
        "undefined",
        "TCP",
        "undefined",
        "EGP",
        "undefined",
        "undefined",
        "undefined",
        "PUP",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "UDP"
};

int
PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp)
{
	int i;
	char buf[80];

	fprintf(fp, "ip--------------------------------------\n");
	fprintf(fp, "version=%u,", iphdr->version);
	fprintf(fp, "ihl=%u,", iphdr->ihl);
	fprintf(fp, "tos=%x,", iphdr->tos);
	fprintf(fp, "tot_len=%u,", ntohs(iphdr->tot_len));
	fprintf(fp, "id=%u\n", ntohs(iphdr->id));
	fprintf(fp, "frag_off=%x,%u,",
		(ntohs(iphdr->frag_off) >> 13) & 0x07,
		ntohs(iphdr->frag_off) & 0x1FFF);
	fprintf(fp, "ttl=%u,", iphdr->ttl);
	fprintf(fp, "protocol=%u", iphdr->protocol);
	if(iphdr->protocol <= 17) {
		fprintf(fp, "(%s),", Proto[iphdr->protocol]);
	}
	else {
		fprintf(fp, "(undefined),");
	}
	fprintf(fp, "check=%x\n", iphdr->check);
	fprintf(fp, "saddr=%s,", ip_ip2str(iphdr->saddr, buf, sizeof(buf)));
	fprintf(fp, "daddr=%s\n", ip_ip2str(iphdr->daddr, buf, sizeof(buf)));
	if(optionLen > 0) {
		fprintf(fp, "option:");
		for(i = 0; i < optionLen; i++) {
			if(i != 0) {
				fprintf(fp, ":%02x", option[i]);
			}
			else{
				fprintf(fp, "%02x", option[i]);
			 }
		}
	}

	return(0);
}


int
PrintUdpHeader(struct udphdr *udphdr, FILE *fp)
{
	int i;
	char buf[80];

	fprintf(fp, "UDP--------------------------------------\n");
	fprintf(fp, "Source Port=%u,", ntohs(udphdr->source));//uh_sport);
	fprintf(fp, "Destination Port=%u,", ntohs(udphdr->dest));//uh_dport);
	fprintf(fp, "Total Len of UDP data=%x,", ntohs(udphdr->len));//uh_ulen);
	//fprintf(fp, "check=%x\n", iphdr->check);
	return(0);
}

// int PrintDnsHeader(struct dnshdr *)