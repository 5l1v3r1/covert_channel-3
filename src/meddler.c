#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <errno.h>

#include "ieee802_11_radio.h"
#include "header.h"
#include "link_list.h"
#include <pcap.h>

#define PACKET_SIZE 1515
#define CRC_BYTES_LEN 4
#define H_MAC_BYTES_LEN 4 /*hmac of the message to be calculated and store. message will be stored in front of HMAC*/
#define MSG_BYTES_LEN 4 /*gives the length of the encrypted message*/
#define TCP_OPTIONS 12 /*TODO: find out the size of the tcp options in the connection from header*/
#define MAX_MESSAGE_SIZE 150

static const u8 u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version
  0x19, 0x00, // <- radiotap header length
  0x6f, 0x08, 0x00, 0x00, // <-- bitmap
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
  0x00, // <-- flags (Offset +0x10)
  0x6c, // <-- rate (0ffset +0x11)
  0x71, 0x09, 0xc0, 0x00, // <-- channel
  0xde, // <-- antsignal
  0x00, // <-- antnoise
  0x01, // <-- antenna

};

static const u8 u8aIeeeHeader[] = {
  0x08, 0x01, 0x00, 0x00,
  //0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xc4, 0x3d, 0xc7, 0x11, 0x22, 0x33,
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66,
  0x10, 0x86,
};

char errbuf[PCAP_ERRBUF_SIZE];
static int idx=-1;
static int ridx=0;

typedef struct global_config {
  int tun_fd;
  int pcap_fd;
  pcap_t* wifi_pcap;
  u_char * key;

  u_char * sender_public_key;
  u_char * sender_private_key;
  
  u_char * receiver_public_key;
  u_char * receiver_private_key;
  
} config_;

config_ config;

int udp_message_len[5];
u_char* udp_message; //[5][150];
static int debug_;
int packet_parse(const unsigned char *, struct timeval, unsigned int);
u_int32_t covert_message_offset(u_int32_t ,u_int32_t , int );
int message_injection(const unsigned char * packet,u_int16_t radiotap_len, u_int32_t capture_len);
int message_reception(const unsigned char * packet, u_int16_t radiotap_len,u_int32_t capture_len);
int framing_covert_message(u_char*,int );
int transmit_on_wifi(u_char *,int);
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
      file_d="phy6";
      pcap=pcap_open_live(file_d, 1500 , 1,20, errbuf);//check the timeout value 
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

int transmit_on_wifi(u_char* frame_to_transmit, int pkt_len)
{
  //open pcap file descripter
  //modify the radiotap IEEE80211_RADIOTAP_F_FCS bit in radiotap 
  u_int32_t r;
  struct ieee80211_radiotap_header * hdr; 
  hdr = (struct ieee80211_radiotap_header *)frame_to_transmit;
  u_int16_t radiotap_len = pletohs(&hdr->it_len);
  printf("in func to transmit frame %u\n",radiotap_len );
  printf("%02x %02x %02x %02x \n",*frame_to_transmit, *(frame_to_transmit+1), *(frame_to_transmit+2),*(frame_to_transmit+3));
  r = pcap_inject(config.wifi_pcap, frame_to_transmit, pkt_len);
  if (r != (pkt_len)){
    perror("Trouble injecting packet");
    return -1;
  }
  printf("transmitted on wifi");
  return 0;
}

u_int32_t covert_message_offset(u_int32_t seq,u_int32_t ack, int pkt_len)
{
  //have to use the shared key of the session to produce this number again!x
  u_int32_t offset=0,i=0,int_digest=0;
  offset =2;
  return offset ;
}

/*
  The function is used to write the covert_message_len, covert_message_hmac,
  encrypted new message.
  [old frame headers | ssl header| old data|hmac| covert_message_len| actual_message_data]
*/
int framing_covert_message(u_char* frame_new_offset,int remaining_len)
{
  //if (remaining_len < udp_message_len[idx])
  //  return -1;
  int a =0;
  u_char * hmac= "this is the new hmac";
  int hmac_s = sizeof("this is the new hmac");
  //encrypt the frame with the key
  //take out the HMAC of the encrypted frame
  memcpy(frame_new_offset,hmac, hmac_s);
  for(a=0;a<5;a++){
    if (udp_message_len[a] ==-1)
      continue;
    memcpy(frame_new_offset,hmac,hmac_s);
    //memcpy(frame_new_offset+hmac_s,(u_char*)&udp_message_len[a],sizeof(udp_message_len[a]));
    //memcpy(frame_new_offset+hmac_s+sizeof(int),udp_message[a], udp_message_len[a]);
  }
  return 0;
}
/*
  The function reads the corrupted frames to see if the frame
  contains the covert message. Strips of the initial bytes to
  get the tun frame that should be written to the tun descriptor

*/
int message_reception(const unsigned char * packet, u_int16_t radiotap_len,u_int32_t capture_len)
{
  printf("#");
  struct ip *ip;
  struct udp_hdr *udp;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len;
  int tcp_options =TCP_OPTIONS; //TCP options
  int bytes_written =0;
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
     { /*Has to be a TCP connection eg. gmail*/
       return -1;
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

    printf("message received ssl v= %02x %02x%02x\n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1), 
	   *((u_int8_t*)(ssl_h)+2) );

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);

    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <MAX_MESSAGE_SIZE+1)
      return -1; /*for now it's mtu=150 bytes*/
    /* TODO:
       use the key to decrypt the length of message following it       
     */
    packet +=message_offset;
    u_char* hmac;
    printf("%02x %02x %02x %02x %02x %02x \n",*packet,*(packet+1), *(packet+2),*(packet+3), *(packet+4),*(packet+5),*(packet+6));
    u_char* ch;
    ch=malloc(7);
    memset(ch,0,7);
    memcpy(ch,packet,7);
    if(!memcmp(ch,"abhinav",7))
      {
        printf("ch abhinav got shit!");
        exit(1);
      }
    if(*packet==0x45){
      printf("got ip packet\n");

      u_char * togo=malloc(35);
      memset(togo,0,35);
      memcpy(togo,packet,35);

      printf("message send to tun driver now\n");
      while(1){
	//Take the message packet and write it to the tun descriptor
	if(bytes_written=write(config.tun_fd,togo,35)<0)
	  {
	    perror("Error in writing the message frame to TUN interface\n");
	    exit(-1);
	  }
	sleep(3);
      }
      free(togo);
    }
    //calculate the hmac of it using function
    /*
    if(!memcmp(calculated_hmac,hmac,sizeof(hmac)))
      { 
	//Take the message packet and write it to the tun descriptor
	if(bytes_written=write(config.tun_fd,message,mesg_size)<0)
	  {
	    perror("Error in writing the message frame to TUN interface\n");
	    exit(-1);
	  }
      }
   */ 
  }  
  return 0;
}
/*
  The function is called when a copy of wireless frame transmitted.
*/
int message_injection(const unsigned char * packet,u_int16_t radiotap_len, u_int32_t capture_len)
{
  printf("message_injection() %d\n",idx);
  if (idx<0){
    return -1; 
  }
  struct ip *ip;
  struct udp_hdr *udp;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len;
  int tcp_options =TCP_OPTIONS; //TCP options

  const u_char* llc_start_p ;
  const u_char* packet_start=packet;
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  struct ieee80211_hdr * sc = (struct ieee80211_hdr *)packet;
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;  
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(mac_hdr_len+8);
  llc_start_p= packet;   
  capture_len -= (mac_hdr_len+8);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP){
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP)
      { /*Has to be a TCP connection*/
	return -1;
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
      return -1; /*there should be content in the traffic*/

    printf("ssl v= %02x %02x%02x \n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1), 
	   *((u_int8_t*)(ssl_h)+2)  );

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);
    const u_char * ssl_hdr_end_p = packet ; 
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

    u_char* frame_to_transmit=NULL;
    int len_frame_to_transmit = 0;
    int copy_len= radiotap_len+ mac_hdr_len+ sizeof(struct ip)+ sizeof(struct llc_hdr)+8+ \
      sizeof(struct tcp_hdr)+TCP_OPTIONS+sizeof(struct ssl_hdr)+message_offset;
    frame_to_transmit=malloc(pkt_len);
    memset(frame_to_transmit,'\0',sizeof(frame_to_transmit));
    u_char* start_frame_to_transmit= frame_to_transmit;
    memcpy(frame_to_transmit, u8aRadiotapHeader,sizeof (u8aRadiotapHeader));
    frame_to_transmit += sizeof (u8aRadiotapHeader);

    memcpy(frame_to_transmit, u8aIeeeHeader, sizeof (u8aIeeeHeader));
    frame_to_transmit += sizeof (u8aIeeeHeader);
     

    memcpy(frame_to_transmit, llc_start_p, ssl_hdr_end_p - llc_start_p );
    frame_to_transmit += ssl_hdr_end_p-llc_start_p;
    memcpy(frame_to_transmit,ssl_hdr_end_p,message_offset);
    frame_to_transmit +=message_offset;

    /*testing*
    memcpy(frame_to_transmit,"abhinav abhinav", sizeof("abhinav abhinav"));
    frame_to_transmit += sizeof("abhinav abhinav");
    */
    u_char * y= udp_message;
    udp_message_len[0]=148;
    printf("udp copied %02x %02x %02x %02x \n",*y, *(y+1), *(y+2),*(y+3));
    memcpy(frame_to_transmit,udp_message,148);
    printf("fr_to_tx: %02x %02x %02x %02x \n",*(frame_to_transmit),*(frame_to_transmit+1),*(frame_to_transmit+2), *(frame_to_transmit+3));
    frame_to_transmit +=udp_message_len[0] ;
    //memcpy(frame_to_transmit,packet_start,copy_len);
    //framing_covert_message(frame_to_transmit+copy_len,remaining_bytes);
    debug_++;
    static int o=0;
    while (o<10){
      printf("pkt size %d %d\n",frame_to_transmit-start_frame_to_transmit,pkt_len);
      transmit_on_wifi(start_frame_to_transmit, pkt_len); //frame_to_transmit-start_frame_to_transmit);      
    }
    o++;
    if (o>10)
        exit(1);
    free(frame_to_transmit);
    if (debug_ >100){
      printf("abhinav: >100\n");
      exit(1);
    }
  }
  return 0 ;
}

int packet_parse(const unsigned char *packet, struct timeval ts,unsigned int capture_len)
{
  u_int16_t radiotap_len=0;
  u_int32_t present=0;
  struct ieee80211_radiotap_header *hdr;
  if (packet ==NULL)
    printf("is null\n");
  hdr = (struct ieee80211_radiotap_header *)packet;
  radiotap_len = pletohs(&hdr->it_len);
  present = pletohl(&hdr->it_present);
  if (capture_len <1400)
    { /*messages are contained in large frames only*/
      return -1;
    }
  if (radiotap_len ==14)
    {
      printf("caplen->%d\n",capture_len);
      message_injection(packet, radiotap_len, capture_len); 
    }
  else 
    { /*need frames that are sent out through device */
     // message_reception(packet, radiotap_len, capture_len); //to be enabled at receiver side
    }
}

int process_tun_frame(u_char* orig_covert_frame, int tun_frame_cap_len)
{
  struct ip *ip;
  struct udp_hdr *udp;
  
  ip = (struct ip *) orig_covert_frame;
  struct ip_packet * p= (struct ip_packet*) orig_covert_frame;
  if (tun_frame_cap_len < ip->ip_hl*4 )
    { /* didn't capture the full IP header including options */
      printf("IP header with options\n");
      return -1;
    }
  //printf("ip offset is offset=%u dont_frag=%u more_frag=%u\n", offset, dont_frag, more_frag);
  //printf("ip morefrags=%u dont_frag=%u frag_offset=%u\n", p->more_frags, p->dont_frag, p->frag_offset);
  
  if (ip->ip_p == IPPROTO_UDP)
    {
      printf("UDP packet on TUN interface\n");
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
    else if (ip->ip_p ==IPPROTO_UDP){
      printf("UDP %d\n", ip->ip_p);
    }
    else
    {
      printf("none of them\n");
    }
  printf("start with copyess_tun_frame %d\n",tun_frame_cap_len);
  // send this on raw socket
  if (idx <0){
  udp_message_len[0]=tun_frame_cap_len;
   // memcpy(udp_message,orig_covert_frame, tun_frame_cap_len);
  printf("done with process_tun_frame %d\n",idx);
  u_char *buf = &udp_message[0];
  printf("copied buf =%02x %02x %02x %02x \n",*buf, *(buf+1), *(buf+2),*(buf+3));
  }
  idx=idx+2;
}


int main()
{
  char buf[PACKET_SIZE];
  char ifname[IFNAMSIZ];
  int tun_frame_cap_len,rad_ret;
  const u_char * radiotap_packet;
  struct pcap_pkthdr header;
  char *mon_interface ="realgmail.pcap";
  config.key = "20142343243243935943uireuw943uihflsdh3otu4tjksdfj43p9tufsdfjp9943u50943";

  config.wifi_pcap= pcap_radiotap_handler(mon_interface);
  if (pcap_setnonblock(config.wifi_pcap, 1, errbuf) == -1) {
    fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    exit(2);
  }
  config.pcap_fd = pcap_get_selectable_fd(config.wifi_pcap);
  //strcpy(ifname, "tun%d");
  strcpy(ifname, "tun2");
  if ((config.tun_fd= tun_alloc(ifname)) < 0) {
    fprintf(stderr, "tunnel interface allocation failed\n");
    exit(1);
  }
  printf("allocted tunnel interface %s\n", ifname);
  int maxfd = (config.tun_fd > config.pcap_fd)?config.tun_fd:config.pcap_fd;
  
  int i=0;
  for(i=0;i<5;i++)
    udp_message_len[i]=-1;

  while(1)
  {
    int ret;
    fd_set rd_set;
    
    FD_ZERO(&rd_set);
    FD_SET(config.tun_fd, &rd_set); 
    FD_SET(config.pcap_fd, &rd_set);
    
    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    
    if (ret < 0 && errno == EINTR){
      continue;
    }
    
    if (ret < 0) {
      perror("select()");
      exit(1);
    }
    if(FD_ISSET(config.tun_fd, &rd_set))
      {
	memset(buf,sizeof(buf), 0);
	if ((tun_frame_cap_len = read(config.tun_fd, buf, sizeof(buf))) < 0) 
	  {
	    perror("read() on tun file descriptor");
	    close(config.tun_fd);
	    exit(1);
	  }
      static int f =0;
      if (!f){
          udp_message=malloc(tun_frame_cap_len);
          memset(udp_message,0,tun_frame_cap_len);
          memcpy(udp_message,buf,tun_frame_cap_len);
          f++;
      }
	u_char *orig_covert_frame= malloc(tun_frame_cap_len);
	memset(orig_covert_frame, tun_frame_cap_len, 0);
	//memcpy(orig_covert_frame,"abhinav abhinav abhinav", sizeof("abhinav abhinav abhinav"));
	memcpy(orig_covert_frame, buf, tun_frame_cap_len);
	printf("%02x %02x %02x %02x \n",*buf, *(buf+1), *(buf+2),*(buf+3));
	printf("read %d bytes from tunnel interface %s.\n-----\n", tun_frame_cap_len, ifname);
	if (idx <0)
	  process_tun_frame (orig_covert_frame, tun_frame_cap_len);
	free(orig_covert_frame);
      }
    if(FD_ISSET(config.pcap_fd, &rd_set))
      {
	radiotap_packet = pcap_next(config.wifi_pcap, &header);
	//printf("main() calling packet_parser() \n");
	rad_ret = packet_parse(radiotap_packet, header.ts, header.caplen);	
      }
  }
  return 0;
}