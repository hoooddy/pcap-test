#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN	0x6
#define TCP_PAYLOAD_LEN	0xb

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};


struct ethernet_hdr{
	u_int8_t ether_dhost[ETHER_ADDR_LEN];
	u_int8_t ether_shost[ETHER_ADDR_LEN];
	u_int16_t ether_type;
};


struct ipv4_hdr{
	u_int8_t ip_hl:4,ip_v:4;
	u_int8_t ip_tos;
	u_int16_t ip_len;
	u_int16_t ip_id;
	u_int16_t ip_off;
	u_int8_t ip_ttl;
	u_int8_t ip_p;
	u_int16_t ip_sum;
	struct in_addr ip_src, ip_dst;
};


struct tcp_hdr{
	u_int16_t th_sport;
	u_int16_t th_dport;
	u_int32_t th_seq;
	u_int32_t th_ack;
	u_int8_t th_x2:4, th_off:4;
	u_int8_t  th_flags;
	u_int16_t th_win;
	u_int16_t th_sum;
	u_int16_t th_urp;
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


struct ethernet_hdr* get_ether_hdr(const u_char* data){
	struct ethernet_hdr *eth_header = (struct ethernet_hdr *)data;

	if(ntohs(eth_header->ether_type) != 0x800)
		return NULL;
	
	return eth_header;
}


struct ipv4_hdr* get_ipv4_hdr(const u_char* data){
	struct ipv4_hdr *ip_header = (struct ipv4_hdr *)data;

	if(ip_header->ip_p != 0x6)
		return NULL;

	return ip_header;
}


struct tcp_hdr* get_tcp_hdr(const u_char* data){
	struct tcp_hdr *tcp_header = (struct tcp_hdr *)data;

	return tcp_header;
}


void print_header_info(struct ethernet_hdr *eth_hdr, struct ipv4_hdr *ip_hdr, struct tcp_hdr *tcp_hdr, const u_char* packet){
	u_int8_t *eth_shost = eth_hdr->ether_shost;
	u_int8_t *eth_dhost = eth_hdr->ether_dhost;

	printf("Ethernet Header's src mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth_shost[0], eth_shost[1], eth_shost[2],
			eth_shost[3], eth_shost[4], eth_shost[5]);
	printf("Ethernet Header's dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
			eth_dhost[0], eth_dhost[1], eth_dhost[2],
			eth_dhost[3], eth_dhost[4], eth_dhost[5]);

	printf("IP Header's src ip        : %s\n", inet_ntoa(ip_hdr->ip_src));
	printf("IP Header's dst ip        : %s\n", inet_ntoa(ip_hdr->ip_dst));

	printf("TCP Header's src port     : %d\n", ntohs(tcp_hdr->th_sport));
	printf("TCP Header's dst port     : %d\n", ntohs(tcp_hdr->th_dport));
	
	printf("TCP Payload[10byte]       : ");

	if(ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4 - tcp_hdr->th_off*4 == 0){
		printf("There is no TCP Payload.\n\n");
		return ;
	}
	
	for (int i = 0; i < 10; i++)
		printf("%02x ", (packet +tcp_hdr->th_off*4)[i]);
	printf("\n\n");
	return ;
} 


int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;	
		struct ethernet_hdr* eth_header;
		struct ipv4_hdr* ip_header;
		struct tcp_hdr* tcp_header;
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		if ((eth_header = get_ether_hdr(packet)) == NULL) continue;

		packet += 14;
		if ((ip_header = get_ipv4_hdr(packet)) == NULL) continue;
		
		packet += 20;
		if ((tcp_header = get_tcp_hdr(packet)) != NULL)
			print_header_info(eth_header, ip_header, tcp_header, packet);	
	}

	pcap_close(pcap);
	return 0;
}
