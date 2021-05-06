char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size);
char *arp_ip2str(u_int8_t *ip,char *buf,socklen_t size);
char *ip_ip2str(u_int32_t ip,char *buf,socklen_t size);
int PrintEtherHeader(struct ether_header *eh,FILE *fp);
int PrintArp(struct ether_arp *arp,FILE *fp);
int PrintIpHeader(struct iphdr *iphdr,u_char *option,int optionLen,FILE *fp);
int PrintIp6Header(struct ip6_hdr *ip6,FILE *fp);
int PrintIcmp(struct icmp *icmp,FILE *fp);
int PrintIcmp6(struct icmp6_hdr *icmp6,FILE *fp);
int PrintTcp(struct tcphdr *tcphdr,FILE *fp);
int PrintUdpHeader(struct udphdr *udphdr,FILE *fp);

//12 bytes dns header
struct dnshdr {
	unsigned short id; // 16-bit identifcation number sometimes called transaction id
	unsigned char rd: 1; // recursion is enabled or not
	unsigned char tc: 1; // truncated message or not
	unsigned char aa: 1; // authorative response or not
	unsigned char opcode: 4; // purpose of message 
	unsigned char qr: 1; // flag for query or response
	
	unsigned char rcode: 4; // response code 
	unsigned char cd: 1; // checking disabled or not
	unsigned char ad: 1; // authenticated data or not
	unsigned char z: 1; 
	unsigned char ra: 1; // recrusion available or not
	unsigned short n_q; // number of question entries
	unsigned short n_a; // number of answer entries
	unsigned short n_auth; // number of authority entries
	unsigned short n_add; // number of additional (resource) entries
};


struct dns_question {
	unsigned short type;
	unsigned short _class;
};

