#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/icmp.h>

#define SOCKET_SCAN 1
#define SYN_SCAN 2
#define FIN_SCAN 3
#define UDP_SCAN 4

#define OPEN 1
#define CLOSE 2
#define UNKNOWN 3

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

struct scaninfo_struct {
	int scan_type;
	char interface[32];
	struct in_addr ipaddr;
	char ipaddr_string[32];
	int startport;
	int endport;
	int portnum;
	int sourceport;
	pthread_cond_t * cond;
	int flags;
	int * portstatus;
	int alreadyscan;
};

struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip {
	u_char ip_vhl;
	u_char ip_tos;
	u_char ip_len;
	u_char ip_id;
	u_char ip_off;
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src, ip_dst;
};

struct sniff_tcp {
	u_short th_sport;
	u_short th_dport;
	u_int32_t th_seq;
	u_int32_t th_ack;
	u_char th_offx2;
	u_char th_flags;
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

void socket_scan(struct scaninfo_struct * pscaninfo) {
	for(int i = pscaninfo->startport; i <= pscaninfo->endport; i++) {
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(i);
		inet_pton(AF_INET, pscaninfo->ipaddr_string, &addr.sin_addr);
		int sock = socket(AF_INET, SOCK_STREAM, 0);
		if(sock == -1) {
			printf("create socket error!\n");
			return ;
		}
		int retval = connect(sock, (const struct sockaddr *)(&addr), sizeof(addr));
		if(retval == 0) {
			pscaninfo->portstatus[i - pscaninfo->startport] = OPEN;
			close(sock);
		}else pscaninfo->portstatus[i - pscaninfo->startport] = CLOSE;
	}
}

void udp_scan(struct scaninfo_struct * pscaninfo) {
	for(int i = pscaninfo->startport; i <= pscaninfo->endport; i++) {
		struct sockaddr_in addr;
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(i);
		inet_pton(AF_INET, pscaninfo->ipaddr_string, &addr.sin_addr);
		int sock = socket(AF_INET, SOCK_DGRAM, 0);
		if(sock == -1) {
			printf("create socket error!\n");
			return ;
		}
		int sockrecv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if(sock < 0) {
			printf("create raw socket error!\n");
			return ;
		}
		int res = sendto(sock, NULL, 0, 0, (struct sockaddr*)&addr, sizeof(addr));
		char buff[1600];
		fd_set select_fd;
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		int retval = 1;
		clock_t time = clock();
		while(clock() - time < CLOCKS_PER_SEC * 2) {
			FD_ZERO(&select_fd);
			FD_SET(sockrecv, &select_fd);
			
			if(select(sockrecv + 1, &select_fd, NULL, NULL, &tv) > 0) {
				struct ip *ip;
				struct icmphdr *icmp;
				int hlen;
				unsigned int port;
				memset(&ip, 0, sizeof(ip));
				if(recvfrom(sockrecv, buff, 1600, 0, NULL, NULL) != 56)
					continue;
				ip = (struct ip*) buff;
				hlen = ip->ip_hl << 2;
				icmp = (struct icmphdr*) (buff + hlen);
				port = (unsigned int)ntohs(*(u_short*)(buff+20+8+20+2));
				if((ip->ip_src.s_addr != addr.sin_addr.s_addr) ||
					(icmp->type != ICMP_UNREACH) ||
					(icmp->code != ICMP_UNREACH_PORT) ||
					(port != i))
					continue;
			}else retval = 0;
			break;
		}
		close(sock);
		close(sockrecv);
		
		if(retval == 0) {
			pscaninfo->portstatus[i - pscaninfo->startport] = OPEN;
			close(sock);
		}else pscaninfo->portstatus[i - pscaninfo->startport] = CLOSE;
	}
}

int sendpacket(const char* ip_src, const char* ip_dst, u_int16_t srcport, u_int16_t dstport, u_int8_t flags, char* device) {
	libnet_t * l;
	char errbuf[LIBNET_ERRBUF_SIZE];
	int ack;
	l = libnet_init(LIBNET_RAW4, device, errbuf);
	if(l == NULL) {
		printf("libnet init: %s\n", errbuf);
		libnet_destroy(l);
		return 1;
	}
	if(flags == TH_SYN)
		ack = 0;
	else
		ack = rand() % 200000 + 200000;
	libnet_ptag_t tcp_tag = libnet_build_tcp(
		srcport,
		dstport,
		rand() % 200000 + 200000,
		ack,
		flags,
		rand() % 3000 + 5000,
		0,
		0,
		LIBNET_TCP_H,
		NULL,
		0,
		l,
		0
	);
	if(tcp_tag == -1) {
		printf("building tcp header error\n");
		libnet_destroy(l);
		return 1;
	}
	libnet_ptag_t ipv4_tag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,
		0,
		0,
		0,
		64,
		IPPROTO_TCP,
		0,
		libnet_name2addr4(l, (char*)ip_src, LIBNET_DONT_RESOLVE),
		libnet_name2addr4(l, (char*)ip_dst, LIBNET_DONT_RESOLVE),
		NULL,
		0,
		l,
		0
	);
	if(ipv4_tag == -1) {
		printf("building ipv4 header error\n");
		libnet_destroy(l);
		return 1;
	}
	int retval = libnet_write(l);
	if(retval == -1) {
		printf("sending packet error\n");
		libnet_destroy(l);
		return 1;
	}
	libnet_destroy(l);
	return 0;
}


#define SIZE_ETHERNET 14

void packet_handler(u_char * args, const pcap_pkthdr * header, const u_char * packet) {
	struct scaninfo_struct * pscaninfo = (struct scaninfo_struct*) args;
	int SIZE_THERNET = 14;
	struct sniff_ethernet * ethernet;
	struct sniff_ip * ip;
	struct sniff_tcp * tcp;
	u_int size_ip;
	u_int size_tcp;
	ethernet = (struct sniff_ethernet *)(packet);
	ip = (sniff_ip *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;
	if(size_ip < 20) {
		printf("Invalid IP header length: %d bytes \n", size_ip);
		return;
	}
	tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if(size_tcp < 20) {
		printf("Invalid TCP header length: %d bytes\n", size_tcp);
		return ;
	}
	int srcport = ntohs(tcp->th_sport);
	int dstport = ntohs(tcp->th_dport);
	if(pscaninfo->scan_type == SYN_SCAN) { // SYN Scan
		if(dstport == pscaninfo->sourceport) {
			if(tcp->th_flags == (TH_SYN|TH_ACK))
				pscaninfo->portstatus[srcport - pscaninfo->startport] = OPEN;
			else
				if((tcp->th_flags & TH_RST) != 0)
					pscaninfo->portstatus[srcport - pscaninfo->startport] = CLOSE;
				else
					pscaninfo->portstatus[srcport - pscaninfo->startport] = UNKNOWN;
			pscaninfo->alreadyscan++;
		}
	}else if(pscaninfo->scan_type == FIN_SCAN) { // FIN Scan
		if(dstport == pscaninfo->sourceport) {
			if((tcp->th_flags & TH_RST) != 0)
				pscaninfo->portstatus[srcport - pscaninfo->startport] = CLOSE;
			else
				pscaninfo->portstatus[srcport - pscaninfo->startport] = UNKNOWN;
			pscaninfo->alreadyscan++;
		}
	}
	
	if(pscaninfo->alreadyscan >= pscaninfo->portnum)
		pthread_cond_signal(pscaninfo->cond);
}

void * receivethread(void *args) {
	struct scaninfo_struct * pscaninfo = (struct scaninfo_struct*) args;
	bpf_u_int32 net;
	bpf_u_int32 mask;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_lookupnet(pscaninfo->interface, &net, &mask, errbuf);
	pcap_t * handle;
	handle = pcap_open_live(pscaninfo->interface, 100, 1, 0, errbuf);
	if(handle == NULL) {
		printf("pcap open device failure!\n");
		return NULL;
	}
	char filter[100] = "tcp port ";
	char tmp[20];
	/////////////////////
	snprintf(tmp, sizeof(tmp), " %d", pscaninfo->sourceport);
	strcat(filter, tmp);
	strcat(filter, " and src host ");
	strcpy(tmp, pscaninfo->ipaddr_string);
	strcat(filter, tmp);
	struct bpf_program fp;
	int retval = 0;
	retval = pcap_compile(handle, &fp, filter, 0, net);
	if(retval == -1)
		return NULL;
	retval = pcap_setfilter(handle, &fp);
	if(retval == -1)
		return NULL;
	pcap_loop(handle, 0, packet_handler, (u_char*) pscaninfo);
	return NULL;
}

void * sendthread(void *args) {
	struct scaninfo_struct * pscaninfo = (struct scaninfo_struct*) args;
	char src_ip[16];
	struct ifreq ifr;
	int sock;
	int i;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(sock == -1) {
		printf("Can not get local ip address\n");
		exit(1);
	}
	strncpy(ifr.ifr_name, pscaninfo->interface, IF_NAMESIZE);//IFNAMESIZ);
	if(ioctl(sock, SIOCGIFADDR, &ifr) == -1) {
		printf("Can not get local ip address\n");
		exit(1);
	}
	struct sockaddr_in sin;
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	const char * tmp = inet_ntoa(sin.sin_addr);
	strncpy(src_ip, tmp, 16);
	for(i = pscaninfo->startport; i <= pscaninfo->endport; i++)
		sendpacket(src_ip, pscaninfo->ipaddr_string, pscaninfo->sourceport, i, pscaninfo->flags, pscaninfo->interface);
	return NULL;
}

void synfin_scan(struct scaninfo_struct * pscaninfo) {
	pthread_t s_thread;
	pthread_t r_thread;
	pthread_cond_t cond;
	pthread_mutex_t mutex;
	struct timeval now;
	struct timespec to;
	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);
	pscaninfo->cond = &cond;
	srand(time(NULL));
	pscaninfo->sourceport = rand() % 2000 + 2000;
	pthread_create(&r_thread, NULL, receivethread, (void*)(pscaninfo));
	usleep(200000);
	pthread_create(&s_thread, NULL, sendthread, (void*)(pscaninfo));
	pthread_join(s_thread, NULL);
	gettimeofday(&now,NULL);
	to.tv_sec = now.tv_sec;
	to.tv_nsec = now.tv_usec * 1000;
	to.tv_sec += 10;
	pthread_cond_timedwait(&cond, &mutex, &to);
	pthread_cancel(r_thread);
	pthread_cond_destroy(&cond);
	pthread_mutex_destroy(&mutex);
}

int parse_scanpara(int argc, char** argv, struct scaninfo_struct* pparse_result) {
	if(argc!=6) {
		printf("The count of parammeters error!\n");
		return 1;
	}
	if(!strcmp(argv[1],"SOCKET_SCAN")) {
		pparse_result->scan_type = SOCKET_SCAN;
	}else if(!strcmp(argv[1],"SYN_SCAN")) {
		pparse_result->scan_type = SYN_SCAN;
	}else if(!strcmp(argv[1],"FIN_SCAN")) {
		pparse_result->scan_type = FIN_SCAN;
	}else if(!strcmp(argv[1],"UDP_SCAN")) {
		pparse_result->scan_type = UDP_SCAN;
	}else{
		printf("An Unsupported scan type!\n");
		return 1;
	}
	strcpy(pparse_result->interface, argv[2]);
	strcpy(pparse_result->ipaddr_string, argv[3]);
	if(inet_aton(argv[3], &pparse_result->ipaddr) == 0) {
		printf("IPaddr format error! please check it!\n");
		return 1;
	}
	pparse_result->startport = atoi(argv[4]);
	pparse_result->endport = atoi(argv[5]);
	pparse_result->portnum = pparse_result->endport - pparse_result->startport + 1;
	pparse_result->alreadyscan = 0;
	pparse_result->portstatus = (int*) malloc(pparse_result->portnum * 4);
	for(int i = 0; i < pparse_result->portnum; i++) {
		pparse_result->portstatus[i] = UNKNOWN;
	}
	if(pparse_result->scan_type == SYN_SCAN) {
		pparse_result->flags = TH_SYN;
	}else if(pparse_result->scan_type == FIN_SCAN) {
		pparse_result->flags = TH_FIN;
	}
	return 0;
}

void output_scanresult(struct scaninfo_struct scaninfo) {
	printf("Scan result of the host(%s):\n", scaninfo.ipaddr_string);
	printf("port status\n");
	for(int i = 0; i < scaninfo.portnum; i++) {
		if(scaninfo.portstatus[i] == OPEN)
			printf("  %d port open\n", scaninfo.startport + i);
		else if(scaninfo.portstatus[i] == CLOSE)
			printf("  %d port close\n", scaninfo.startport + i);
		else
			printf("  %d port unknown\n", scaninfo.startport + i);
		
	}
}

int main(int argc, char** argv) {
	struct scaninfo_struct scaninfo;
	if(parse_scanpara(argc, argv, &scaninfo)) {
		printf("Usage %s SOCKET_SCAN/SIN_SCAN/FIN__SCAN interface IPaddr startport endport\n", argv[0]);
		return 1;
	}
	if(scaninfo.scan_type == SOCKET_SCAN)
		socket_scan(&scaninfo);
	else if(scaninfo.scan_type == UDP_SCAN)
		udp_scan(&scaninfo);
	else if( scaninfo.scan_type == SYN_SCAN || scaninfo.scan_type == FIN_SCAN)
		synfin_scan(&scaninfo);
	else {
		printf("Unsupported scan type!");
		return 1;
	}
	output_scanresult(scaninfo);
	return 0;
}
