#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct eth_hdr {
	uint8_t dest_mac[6];	// destination MAC (6byte)
	uint8_t source_mac[6];	// source MAC (6byte)
	uint16_t eth_type;	// Ethernet Type (2byte)
}eth_hdr;

typedef struct ip_hdr {
	uint8_t ip_hl:4;		// ip header length (4bit) (Little Endian)
	uint8_t ip_ver:4;		// ip version (4bit) (Little Endian)
	uint8_t ip_tos;		// ip type of service (1byte)
	uint16_t ip_len;		// ip total length (2byte)
	uint16_t ip_id;		// ip identifier (2byte)
	uint16_t ip_off;		// ip fragment offset field (2byte)
	uint8_t ip_ttl;		// ip time to live (1byte)
	uint8_t ip_pro;		// ip protocol (1byte)
	uint16_t ip_check;	// ip checksum (2byte)
	struct in_addr ip_src, ip_dest;	// ip address (each 4byte)
}ip_hdr;

typedef struct tcp_hdr {
	uint16_t port_src;	// tcp source port (2byte)
	uint16_t port_dest;	// tcp destination port (2byte)
	uint32_t tcp_seq;		// tcp sequence number (4byte)
	uint32_t tcp_ack;		// tcp acknowledgement number (4byte)
	uint8_t tcp_blank:4;	// tcp reserved field (4bit, Little Endian) - 2bit to flag
	uint8_t tcp_hlen:4;	// tcp header length (4bit, Little Endian)
	uint8_t tcp_flags;	// tcp flags (8bit) - 2bit from Reserved
	uint16_t tcp_wnd;		// tcp window size (2byte)
	uint16_t tcp_checksum;	// tcp checksum (2byte)
	uint16_t tcp_urgpnt;	// tcp urgent pointer (2byte)
}tcp_hdr;


void dump(const uint8_t* p, int len) {
	for(int i=0; i<len; i++) {
		printf("%02x ", *p);
		p++;
		if((i & 0x0f) == 0x0f)
			printf("\n");
	}
}

void print_mac(uint8_t *mac, int len) {
	for(int i=0;i<len;i++)
	{
		printf("%02x", mac[i]);
		if(i<5)
			printf(":");
	}
}

void parse(const uint8_t* p, eth_hdr* ETH, ip_hdr* IP, tcp_hdr* TCP, int len) {
	const u_char* tmp;
	ETH = (eth_hdr *)p;
	p +=  sizeof(eth_hdr);
	if(ntohs(ETH->eth_type) == ETHERTYPE_IP)
	{
		IP = (ip_hdr* )p;
		p += 4*(IP->ip_hl);
		if(IP->ip_pro == IPPROTO_TCP)
		{
			printf("----------------------------------------------\n");
			printf("%ubyte TCP Packet Captured\n", len);
			TCP = (tcp_hdr* )p;
			p += 4*(TCP->tcp_hlen);
			printf("-----------Ethernet-----------\n");
			printf("Source MAC : ");
			print_mac(ETH->source_mac);
			printf("\nDestination MAC : ");
			print_mac(ETH->dest_mac);
			printf("\n--------------IP--------------\n");
			printf("Source IP : %s\n", inet_ntoa(IP->ip_src));
			printf("Destination IP : %s\n", inet_ntoa(IP->ip_dest));
			printf("--------------TCP-------------\n");
			printf("Source Port : %u\n",ntohs(TCP->port_src));
			printf("Destination Port : %u\n",ntohs(TCP->port_dest));
			int newlen = ip_len - ip_hl*4 - tcp_hlen*4;
			newlen = (newlen < 32) ? newlen : 32
			dump(p, newlen);
			printf("\n\n");
		}
	}
	return;
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    eth_hdr *ETH;
    ip_hdr *IP;
    tcp_hdr *TCP;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    parse(packet, ETH, IP, TCP, header->caplen); 
    // printf("DEBUG DUMP\n"); dump((u_char* )packet, header->caplen);printf("\n\n"); //(FOR DEBUGGING)
  }

  pcap_close(handle);
  return 0;
}
