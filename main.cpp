#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct eth_hdr {
	unsigned char dest_mac[6];	// destination MAC (6byte)
	unsigned char source_mac[6];	// source MAC (6byte)
	unsigned short eth_type;	// Ethernet Type (2byte)
}eth_hdr;

typedef struct ip_hdr {
	unsigned int ip_hl:4;		// ip header length (4bit) (Little Endian)
	unsigned int ip_ver:4;		// ip version (4bit) (Little Endian)
	unsigned char ip_tos;		// ip type of service (1byte)
	unsigned short ip_len;		// ip total length (2byte)
	unsigned short ip_id;		// ip identifier (2byte)
	unsigned short ip_off;		// ip fragment offset field (2byte)
	unsigned int ip_ttl:8;		// ip time to live (1byte)
	unsigned int ip_pro:8;		// ip protocol (1byte)
	unsigned short ip_check;	// ip checksum (2byte)
	struct in_addr ip_src, ip_dest;	// ip address (each 4byte)
}ip_hdr;

typedef struct tcp_hdr {
	unsigned short port_src;	// tcp source port (2byte)
	unsigned short port_dest;	// tcp destination port (2byte)
	unsigned int tcp_seq;		// tcp sequence number (4byte)
	unsigned int tcp_ack;		// tcp acknowledgement number (4byte)
	unsigned int tcp_blank:4;	// tcp reserved field (4bit, Little Endian) - 2bit to flag
	unsigned int tcp_hlen:4;	// tcp header length (4bit, Little Endian)
	unsigned char tcp_flags;	// tcp flags (8bit) - 2bit from Reserved
	unsigned short tcp_wnd;		// tcp window size (2byte)
	unsigned short tcp_checksum;	// tcp checksum (2byte)
	unsigned short tcp_urgpnt;	// tcp urgent pointer (2byte)
}tcp_hdr;


void dump(const u_char* p, int len) {
	for(int i=0; i<len; i++) {
		printf("%02x ", *p);
		p++;
		if((i & 0x0f) == 0x0f)
			printf("\n");
	}
}


void parse(const u_char* p, eth_hdr* ETH, ip_hdr* IP, tcp_hdr* TCP, int len) {
	const u_char* tmp;
	ETH = (eth_hdr *)p;
	p +=  sizeof(eth_hdr);
	if(ntohs(ETH->eth_type) == 0x0800)
	{
		IP = (ip_hdr* )p;
		p += 4*(IP->ip_hl);
		if(IP->ip_pro == 0x06)
		{
			printf("----------------------------------------------\n");
			printf("%ubyte TCP Packet Captured\n", len);
			TCP = (tcp_hdr* )p;
			p += 4*(TCP->tcp_hlen);
			printf("Ethernet\n");
			printf("Source MAC : ");
			for(int i=0;i<6;i++)
			{
				printf("%02x", ETH->source_mac[i]);
				if(i<5)
					printf(":");
			}
			printf("\nDestination MAC : ");
			for(int i=0;i<6;i++)
			{
				printf("%02x", ETH->dest_mac[i]);
				if(i<5)
					printf(":");
			}
			printf("\nIP\n");
			printf("Source IP : %s\n", inet_ntoa(IP->ip_src));
			printf("Destination IP : %s\n", inet_ntoa(IP->ip_dest));
			printf("TCP\n");
			printf("Source Port : %u\n",ntohs(TCP->port_src));
			printf("Destination Port : %u\n",ntohs(TCP->port_dest));
			int newlen = len - sizeof(eth_hdr) - 4*(IP->ip_hl) - 4*(TCP->tcp_hlen);
			if(newlen<=32) {
				dump(p, newlen);
			}
			else {
				dump(p, 32);
				printf("...");
			}
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
