#include <pcap.h>
#include <stdio.h>

typedef struct eth_header {
	unsigned char dest_mac[6];	// destination MAC (6byte)
	unsigned char source_mac[6];	// source MAC (6byte)
	unsigned short eth_type;	// Ethernet Type (2byte)
};

typedef struct ip_header {
	unsigned int ip_ver:4;		// ip Version (4bit)
	unsigned int ip_hl:4;		// ip header length (4bit)
	unsigned char ip_tos;		// ip type of service (1byte)
	unsigned short ip_len;		// ip total length (2byte)
	unsigned short ip_id;		// ip identifier (2byte)
	unsigned short ip_off;		// ip fragment offset field (2byte)
	unsigned int ip_ttl:8;		// ip time to live (1byte)
	unsigned int ip_pro:8;		// ip protocol (1byte)
	unsigned short ip_check;	// ip checksum (2byte)
	struct in_addr ip_src, ip_dest;	// ip address (each 4byte)
};


void dump(const u_char* p, int len) {
  for(int i=0; i< len; i++) {
	  printf("%02x ", *p);
	  p++;
	  if((i & 0x0f) == 0x0f)
		  printf("\n");
  }
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
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    dump((u_char*)(packet), header->caplen);
    printf("\n\n");
  }

  pcap_close(handle);
  return 0;
}
