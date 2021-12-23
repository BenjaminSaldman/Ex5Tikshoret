#include <stdio.h>
#include "headers.h"
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};
struct icmphdr{
	#define ICMP_ECHO_REQ 8
	#define ICMP_ECHO_RES 0
	#define ICMP_HDR_LEN 4
 	unsigned char icmp_type;
 	unsigned char icmp_code;
 	unsigned short icmp_cksum;		/* icmp checksum */
 	unsigned short icmp_id;				/* icmp identifier */
 	unsigned short icmp_seq;			/* icmp sequence number */
};
/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

      

    /* determine protocol */
    switch(ip->iph_protocol) {                               
       
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            printf("Source: %s\n", inet_ntoa(ip->iph_sourceip));  
            printf("Dest: %s\n", inet_ntoa(ip->iph_destip)); 
            struct icmphdr *icmp_hdr = (struct icmphdr *)((char *)ip  + (4 * ip->iph_ihl));
            printf("Type=%d, Code=%d", icmp_hdr->icmp_type, icmp_hdr->icmp_code);
            printf("\n");
            return;
    }
  }
}

int main()
{
 
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); 
  if (handle == NULL) {
    fprintf(stderr, "Can't open eth3: %s\n", errbuf);
    return 1;
}

//   // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);      
      pcap_setfilter(handle, &fp);                             

//   // Step 3: Capture packets
      pcap_loop(handle, -1, got_packet, NULL);                

   pcap_close(handle);   //Close the handle 
  return 0;


}