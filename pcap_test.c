#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

// Ethernet Header struct
struct ether_header* ep;

// IP Header struct
struct ip* iph;

// TCP Header struct
struct tcphdr* tcph;


void print(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet){
  static int count = 1;
  unsigned short ether_type;
  u_char* ether_dhost;
  u_char* ether_shost;
  char* ip_dhost;
  char* ip_shost;
  u_int8_t tcp_dport;
  u_int8_t tcp_sport;
  int chcnt = 0;
  int length = pkthdr->len;
  int i;

  // get ethernet header
  ep = (struct ether_header*)packet;

  // add offset to get IP Header
  packet += sizeof(struct ether_header);
  
  // get protocol type, dst mac and src mac
  ether_type = ntohs(ep->ether_type);
  ether_dhost = ep->ether_dhost;
  ether_shost = ep->ether_shost;
  
  if(ether_type == ETHERTYPE_IP){
    iph = (struct ip*)packet;
    ip_dhost = inet_ntoa(iph->ip_dst);
    ip_shost = inet_ntoa(iph->ip_src);

    if(iph->ip_p == IPPROTO_TCP){
      tcph = (struct tcp*)(packet + iph->ip_hl * 4);
      tcp_dport = ntohs(tcph->source);
      tcp_sport = ntohs(tcph->dest);

      // print
      i = 6;
      printf("[");
      do{
	printf("%s%02x", (i == 6) ? "" : ":", *(ether_shost++));
      }while(--i > 0);
            
      printf("]%s:%d\t --> \t", ip_shost, tcp_sport);

      printf("[");
      i = 6;
      do{
	printf("%s%02x", (i == 6) ? "" : ":", *(ether_dhost++));
      }while(--i > 0);
      printf("]%s:%d\n", ip_dhost, tcp_dport);
    }else{
      // TODO: if packet is not tcp
    }
  }else{
    // TODO: if packet is not ip
  }
}
	


int main(int argc, char **argv){
  char* dev;  // using network device name
  char* net;  // network address
  char* mask; // network mask address
  int ret;
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp;  // ip
  bpf_u_int32 maskp; // subnet mask
  struct in_addr net_addr, mask_addr;
  struct pcap_pkthdr hdr;
  const u_char *packet;

  struct bpf_program fp;
  
  pcap_t* pcd;  // packet capture descriptor

  if(argc < 2){
    printf("Usage: pcap_test capture_count\nIf capture_count is 0, i won't be end until Ctrl+C\n");
    exit(1);
  }
  
  // get network device name
  dev = pcap_lookupdev(errbuf);

  // error handling
  if(dev == NULL){
    printf("%s\n", errbuf);
    exit(1);
  }

  // print network device name
  printf("DEV: %s\n", dev);

  // get network device name, mask and ip address
  ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

  if(ret == -1){
    printf("%s\n", errbuf);
    exit(1);
  }
  
  // convert ip address to dot style
  net_addr.s_addr = netp;
  net = inet_ntoa(net_addr);

  if(net == NULL){
    perror("inet_ntoa");
    exit(1);
  }
  printf("NET: %s\n", net);

  // convert mask to dot style
  mask_addr.s_addr = maskp;
  mask = inet_ntoa(mask_addr);
  printf("MSK : %s\n", mask);
  printf("----------------------------------\n");
  
  // get packet capture descriptor of dev
   pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
  if(pcd == NULL){
    printf("%s\n", errbuf);
    exit(1);
  }

  // packet capture
  pcap_loop(pcd, atoi(argv[1]), print, NULL);

  return 0;
}

