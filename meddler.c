#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <linux/if_tun.h>
#include <netinet/if_ether.h>

#include <netinet/in.h>
#include <net/if.h>

#include "include/ieee802_11_radio.h"
#include "include/header.h"
#include <math.h>
#include <pcap.h>

#define PACKET_SIZE 1515
#define CRC_BYTES_LEN 4
#define H_MAC_BYTES_LEN 4 /*hmac of the message to be calculated and store. message will be stored in front of HMAC*/
#define MSG_BYTES_LEN 4 /*gives the length of the encrypted message*/
#define TCP_OPTIONS 12 /*TODO: find out the size of the tcp options in the connection from header*/
#define MAX_MESSAGE_SIZE 150
char errbuf[PCAP_ERRBUF_SIZE];

struct ip_packet {
  uint header_len:4;       /* header length in words in 32bit words */
  uint version:4;          /* 4-bit version */
  uint serve_type:8;       /* how to service packet */
  uint packet_len:16;      /* total size of packet in bytes */
  uint ID:16;              /* fragment ID */
  uint frag_offset:13;     /* to help reassembly */
  uint more_frags:1;       /* flag for "more frags to follow" */
  uint dont_frag:1;        /* flag to permit fragmentation */
  uint __reserved:1;       /* always zero */
  uint time_to_live:8;     /* maximum router hop count */
  uint protocol:8;         /* ICMP, UDP, TCP */
  uint hdr_chksum:16;      /* ones-comp. checksum of header */
  u_char IPv4_src[4]; /* IP address of originator */
  u_char IPv4_dst[4]; /* IP address of destination */
  u_char options[0];        /* up to 40 bytes */
  u_char data[0];           /* message data up to 64KB */
};

struct global_config {
  int tun_fd;
  pcap_t* wifi_pcap=NULL;
  u_char * tun_frame;
  int tun_frame_len;
  u_char * key;
} ;
struct global_config config;
static int debug_;
void packet_parse(const unsigned char *, struct timeval, unsigned int);
u_int32_t covert_message_offset(u_int32_t ,u_int32_t , int );
int framing_covert_message(u_char*,int );
int transmit_on_wifi(u_char *);
int tun_alloc(char *);


int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (*dev)
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);

    return fd;
}

pcap_t * pcap_radiotap_handler(char * file_d){
  pcap_t *pcap;
  if (0)
    pcap = pcap_open_offline(file_d, errbuf);
  else
    {
      file_d="phy0";
      pcap=pcap_open_live(file_d, 1500 , -1, errbuf);
    }
  if( pcap == NULL)
    {
      fprintf(stderr, "error reading pcap file: %s\n", errbuf);
      exit(1);
    }
  switch (pcap_datalink(pcap)) {
  case DLT_IEEE802_11_RADIO:
    printf("radiotap data link type");
    break;
  default:
    printf("wrong data link type\n");
    return NULL;
  }
  pcap_setnonblock(pcap, 1, errbuf);
  return pcap;
}

int transmit_on_wifi(u_char* frame_to_transmit)
{
  //open pcap file descripter
  //modify the radiotap IEEE80211_RADIOTAP_F_FCS bit in radiotap 
  r = pcap_inject(config.wifi_pcap, frame_to_transmit, pu8 - u8aSendBuffer);
  if (r != (pu8-u8aSendBuffer)) {
    perror("Trouble injecting packet");
    return (1);
  }

}

u_int32_t covert_message_offset(u_int32_t seq,u_int32_t ack, int pkt_len)
{
  u_int32_t offset=0,i=0,int_digest=0;
  offset =32;

  return offset ;
}

/*
  The function is used to write the covert_message_len, covert_message_hmac,
  encrypted new message.
  [old frame headers | ssl header| old data|hmac| covert_message_len| actual_message_data]
*/
int framing_covert_message(u_char* frame_new_offset,int remaining_len)
{
  if (remaining_len < config.tun_frame_len)
    return -1;
  int a =0;
  u_char * hmac= "this is the new hmac";
  int hmac_s = sizeof("this is the new hmac");
  //encrypt the frame with the key
  //take out the HMAC of the encrypted frame
  memcpy(frame_new_offset,hmac, hmac_s);
  memcpy(frame_new_offset+hmac_s,(u_char*)&config.tun_frame_len,sizeof(config.tun_frame_len));
  memcpy(frame_new_offset+hmac_s+sizeof(int), config.tun_frame, config.tun_frame);
  return 0;
}
/*
  The function reads the corrupted frames to see if the frame
  contains the covert message. Strips of the initial bytes to
  get the tun frame that should be written to the tun descriptor

*/
int message_reception(const unsigned char * packet)
{
  
  return 0;
}
/*
  The function is called when a copy of wireless frame transmitted
*/
int message_injection(const unsigned char * packet,u_int16_t radiotap_len, u_int32_t capture_len)
{
  struct ip *ip;
  struct udp_hdr *udp;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len;
  int tcp_options =TCP_OPTIONS; //TCP options

  packet += radiotap_len;
  capture_len -= radiotap_len;
  const u_char* packet_start=packet;
  fc = EXTRACT_LE_16BITS(packet);
  struct ieee80211_hdr * sc = (struct ieee80211_hdr *)packet;
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;  
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(mac_hdr_len+8);
  capture_len -= (mac_hdr_len+8);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP){
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP)
      { /*Has to be a TCP connection*/
	return;
      }
    packet += IP_header_length;
    capture_len -= IP_header_length;
    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    message_offset = covert_message_offset(ntohl(tcp_h->seq),ntohl(tcp_h->ack),pkt_len);
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    if (ssl_h->ssl_content_type != 0x17)
      return ; /*there should be content in the traffic*/

    printf("ssl v= %02x %02x%02x %02x%02x \n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1), 
	   *((u_int8_t*)(ssl_h)+2), *((u_int8_t*)(ssl_h)+3), *((u_int8_t*)(ssl_h)+4) );

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);

    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <MAX_MESSAGE_SIZE+1)
      return; /*for now it's mtu=150 bytes*/
    /* TODO:
       Encrypt message
       Copy mesg length
       Encrypt part of message
       Copy the message at offset
       Calculate HMAC
       Copy HMAC
       Transmit
     */
    char* frame_to_transmit=NULL;
    int copy_len= radiotap_len+ mac_hdr_len+sizeof(struct ip)+ sizeof(struct llc_hdr)+8+ \
      sizeof(struct tcp_hdr)+TCP_OPTIONS+sizeof(struct ssl_hdr)+message_offset;
    frame_to_transmit=malloc(pkt_len-CRC_BYTES_LEN);
    memset(frame_to_transmit,'\0',sizeof(frame_to_transmit));
    memcpy(frame_to_transmit,packet_start,copy_len);
    framing_covert_message(frame_to_transmit+copy_len,remaining_bytes);
    debug_++;
    transmit_on_wifi(frame_to_transmit);
    free(frame_to_transmit);
    if (debug_ >100)
      exit(1);
  }
  return 0 ;
}
void packet_parse(const unsigned char *packet, struct timeval ts,unsigned int capture_len)
{
  u_int16_t radiotap_len=0;
  u_int32_t present=0;
  struct ieee80211_radiotap_header *hdr;
  hdr = (struct ieee80211_radiotap_header *)packet;
  radiotap_len = pletohs(&hdr->it_len);
  present = pletohl(&hdr->it_present);
  if (capture_len <1400)
    { /*messages are contained in large frames only*/
      return ;
    }
  if (radiotap_len !=14)
    {
      message_reception(packet);      
    }
  else 
    {/*need frames that are sent out through device */
      message_injection(packet,radiotap_len, capture_len);
    }
}



int main()
{
  char buf[PACKET_SIZE];
  char ifname[IFNAMSIZ];
  int tun_frame_cap_len, fd;
  struct ip *ip;
  struct udp_hdr *udp;
  u_char * radiotap_packet=NULL;
  struct pcap_pkthdr header;
  char *mon_interface ="realgmail.pcap";
  config.wifi_pcap= pcap_radiotap_handler(mon_interface);
  config.key = "20142343243243935943uireuw943uihflsdh3otu4tjksdfj43p9tufsdfjp9943u50943";
  //strcpy(ifname, "tun%d");
  strcpy(ifname, "tun2");
  if ((fd = tun_alloc(ifname)) < 0) {
    fprintf(stderr, "tunnel interface allocation failed\n");
        exit(1);
  }

  config.tun_fd=fd;
  printf("allocted tunnel interface %s\n", ifname);

  for (;;) {
    memset(buf,sizeof(buf), 0);
    if ((tun_frame_cap_len = read(fd, buf, sizeof(buf))) < 0) {
      perror("read() on tun file descriptor");
      close(fd);
      exit(1);
    }
    u_char *orig_covert_frame= malloc(tun_frame_cap_len);
    memset(orig_covert_frame, tun_frame_cap_len, 0);
    memcpy(orig_covert_frame, buf, tun_frame_cap_len);
    ip = (struct ip *) orig_covert_frame;
    struct ip_packet * p= (struct ip_packet*) orig_covert_frame;
    if (tun_frame_cap_len < ip->ip_hl*4 )
      { /* didn't capture the full IP header including options */
	printf("IP header with options\n");
	continue;
      }
    
    u_int16_t frag_offset =ntohs(ip->ip_off);
    u_int8_t dont_frag = frag_offset && 0x2;
    u_int8_t more_frag = frag_offset && 0x3;
    u_int16_t offset = frag_offset>>3 ;
    printf("ip offset is offset=%u dont_frag=%u more_frag=%u\n", offset, dont_frag, more_frag);
    printf("ip morefrags=%u dont_frag=%u frag_offset=%u\n", p->more_frags, p->dont_frag, p->frag_offset);

    if (ip->ip_p == IPPROTO_UDP)
      {
	printf("UDP packet\n");
	/* Skip over the IP header to get to the UDP header. */
	orig_covert_frame += ip->ip_hl*4;
	udp = (struct udp_hdr*)orig_covert_frame;
	printf("UDP src_port=%d dst_port=%d length=%d\n",
	       ntohs(udp->uh_sport),
	       ntohs(udp->uh_dport),
	       ntohs(udp->uh_ulen));
      }
    else if (ip->ip_p == IPPROTO_TCP)
      {
	printf("TCP packet %d\n",ip->ip_p);
      }
    else {
      printf("none of TCP/UDP \n");
      continue;
    }
    config.tun_frame=orig_covert_frame;
    config.tun_frame_len=tun_frame_cap_len;
    printf("read %d bytes from tunnel interface %s.\n-----\n", tun_frame_cap_len, ifname);
    while (1){
      radiotap_packet = pcap_next(config.wifi_pcap, &header);
      packet_parse(radiotap_packet, header.ts, header.caplen);
  }    
  return 0;
}
