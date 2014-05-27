#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <zlib.h>
#include <string.h>
#include <stdlib.h>
#include "ieee802_11_radio.h"
#include "header.h"
#include "config.h"
#include "link_list.h"
#include "cryptozis.h"


static int cnt=0;
static int c_128=0, c_48=0;

u_int32_t total_byte=0;
struct timeval first_pkt_time;
struct timeval last_pkt_time;
int global_counter =0;

int static modulo=1;
static int g_pkt_send=0;
static int g_pkt_recv=0;
int debug=0;
#define OFFSET_RATE 0x11
int nRateIndex=0;

static const u8 u8aRatesToUse[] = {
  54*2,
  48*2,
  36*2,
  24*2,
  18*2,
  12*2,
  9*2,
  11*2,
  11, // 5.5
  2*2,
  1*2
};

static int list_size =0;
/*
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

  };*/
static const u8 u8aRadiotapHeader[] = {

  0x00, 0x00, // <-- radiotap version
  0x0d, 0x00, // <- radiotap header length
  0x04, 0x08, 0x20, 0x00, // <-- bitmap
  //  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
  //  0x00, // <-- flags (Offset +0x10)
  0x60, // <-- rate (0ffset +0x11)
  0x71, 0x00, 0x00, 0x00, // <-- channel

};



u8 u8aIeeeHeader[] = {
  0x08, 0x01, 0x00, 0x00,  //data frame
  //0x08, 0x01, 0x00, 0x00, beacon
  //0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x13, 0x22, 0x33, 0x44, 0x55, 0x66, //bssid mac
  0x13, 0x11, 0x33, 0x44, 0x55, 0x66, //source mac
  0x13, 0x11, 0x33, 0x44, 0x55, 0x66, //destination mac
  0x10, 0x86, //sequence no.
};

char errbuf[PCAP_ERRBUF_SIZE];
config_ config;

int packet_parse(const unsigned char *, struct timeval, unsigned int pkt_len);
u_int32_t covert_message_offset(u_int32_t ack,u_int32_t seq, unsigned int pkt_len);
int message_injection(const unsigned char * packet, u_int16_t radiotap_len, u_int32_t capture_len);
int message_reception(const unsigned char * packet, u_int16_t radiotap_len,u_int32_t capture_len);
int transmit_on_wifi(pcap_t*,u_char *,int);
int tun_allocation(char *);

int tun_allocation(char *dev)
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

pcap_t * pcap_radiotap_handler(char * monitor_interface)
{
  pcap_t *pcap;
  pcap=pcap_open_live(monitor_interface, 1536 , 1,20, errbuf);//check the timeout value
if( pcap == NULL)
 {
fprintf(stderr, "error reading pcap file: %s\n", errbuf);
exit(1);
 }
/*
switch (pcap_datalink(pcap)) {
case DLT_IEEE802_11_RADIO:
    printf("radiotap data link type\n");
    break;
    default:
    printf("wrong data link type\n");
    return NULL;
    }
  */
  return pcap;
}

int transmit_on_wifi(pcap_t* pd,
		     u_char* fr_to_tx,
		     int pkt_len)
{
  //open pcap file descripter
  //modify the radiotap IEEE80211_RADIOTAP_F_FCS bit in radiotap
  u_int32_t r;
  struct ieee80211_radiotap_header * hdr;
  hdr = (struct ieee80211_radiotap_header *)fr_to_tx;
  u_int16_t radiotap_len = pletohs(&hdr->it_len);
  r = pcap_inject(pd, fr_to_tx, pkt_len);
  if (r != (pkt_len)){
    perror("Trouble injecting packet");
    return -1;
  }
  printf("transmitted on wifi");
  return 0;
}

u_int32_t covert_message_offset(u_int32_t seq,u_int32_t ack, u_int32_t pkt_len)
{
  //have to use the shared key of the session to produce this number again!
  u_int32_t offset=0;
  u_int32_t temp=0;
  temp=ack+5*seq;
  u_char*str = (u_char*)&temp;
  int c;
  int i=0;
  unsigned long hash = 5676; //encoding of shared key f=f^ord(a[i])
  for(i=0;i<4;i++){
    c=str[i];
    hash= ((hash<< 5) +hash) +c;

  }
  offset=hash %600;
  printf("offset=%d\n",offset);
  return offset ;
}


/*
  The function reads the corrupted frames to see if the frame
  contains the covert message. Strips of the initial bytes to
  get the tun frame that should be written to the tun descriptor

*/
int message_reception(const unsigned char * packet,
		      u_int16_t radiotap_len,
		      u_int32_t capture_len)
{
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc,covert_msgblob_size =0;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len;
  int tcp_options =TCP_OPTIONS; //TCP options
  int bytes_written=0;
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(mac_hdr_len/*+8 */); //TODO: FIXME: Does not work with adding 8 bytes
  capture_len -= (mac_hdr_len /* +8*/);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection eg. gmail*/
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
    //printf("message received bef ssl v= %02x %02x%02x\n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),  *((u_int8_t*)(ssl_h)+2) );
    if (ssl_h->ssl_content_type != 0x17) {
      //printf("not 17\n");
      return -1; /*there should be content in the traffic*/
    }

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);

    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <MAX_MTU_SIZE+1) {
      return -1; /*for now it's mtu=150 bytes*/
    }
    /* TODO:
       use the key to decrypt the length of message following it
    */
    packet +=message_offset;
    u_char c=0;
    memcpy(&c,packet,1);
    packet +=1;
    memcpy((u_char*)&covert_msgblob_size,packet,SHORT_SIZE);
    packet +=SHORT_SIZE;
    printf("%02x %02x %02x %02x %02x %02x \n",*packet,*(packet+1), *(packet+2),*(packet+3), *(packet+4),*(packet+5));
    u_char* encrypt_msg;
    encrypt_msg = malloc((size_t)covert_msgblob_size);
    memset(encrypt_msg,0,(size_t)covert_msgblob_size);
    memcpy(encrypt_msg,packet,(size_t)covert_msgblob_size);
    int return_val=0;
    int noms_rcvd=0;
    noms_rcvd= covert_msgblob_size/(128+SHA_SIZE);
    int u;
    int accum=0;
    for(u=0;u<noms_rcvd;u++)
      {
	u_char* hmac;
	u_char* cipher_tun_frame;
	u_char* decrypted_tun_frame;
	u_char* sha_decr_frame;
	u_char* blob;
	int frame_len, decrypted_tun_frame_len;
	if (c & 1<<u) {
	  frame_len =48; decrypted_tun_frame_len=48;
	} else {
	  frame_len =128; decrypted_tun_frame_len=128;
	}
	//printf("accum=%d\n",accum);
	blob=encrypt_msg+accum; //(128+SHA_SIZE)*u;
	accum = accum + (SHA_SIZE+frame_len);
	hmac=malloc(SHA_SIZE);
	cipher_tun_frame=malloc((size_t)frame_len);
	memset(hmac,0,SHA_SIZE);
	memset(cipher_tun_frame,0,frame_len);
	memcpy(hmac,blob,SHA_SIZE);
	memcpy(cipher_tun_frame,(u_char*)(blob+SHA_SIZE),frame_len);
	sha_decr_frame = HMAC(EVP_sha256(), config.shared_key, config.shared_key_len ,cipher_tun_frame,frame_len, NULL, NULL);
	if (sha_decr_frame ==NULL) {
	  printf("calculated sha is null value");
	  continue;
	}
	return_val =decrypt_digest(&config.de, cipher_tun_frame, \
				   &decrypted_tun_frame, (int*)&decrypted_tun_frame_len);
	if (return_val <0) {
	  printf("decr fail ");
	  free(hmac);
	  free(cipher_tun_frame);
	  continue;
	}
	//u_char *t =decrypted_tun_frame;
	//printf("decrypted correctly; ip:%02x %02x %02x %02x \n",*t,*(t+1),*(t+2),*(t+3));
	if(!memcmp(sha_decr_frame,hmac,SHA_SIZE)) {
	  if (decrypted_tun_frame_len ==124)
	    c_128++;
	  else if (decrypted_tun_frame_len ==42)
	    c_48++;
	  else {
	    printf("some random length %d\n", decrypted_tun_frame_len);
	    exit(1);
	  }
	  //printf("ip:%02x %02x %02x %02x \n",*t,*(t+1),*(t+2),*(t+3));
	  printf("map=%d 48=%d, 128=%d len=%d\n",c,c_48,c_128,decrypted_tun_frame_len);
	  //printf("correct SHA and shoving to TUN %d\n",decrypted_tun_frame_len);
	  if((bytes_written=write(config.tun_fd,decrypted_tun_frame,decrypted_tun_frame_len))<0) {
	    perror("Error in writing the message frame to TUN interface\n");
	    continue;
	  }
	  else {
	    //printf("packet is written to tun driver yay!\n");
	    if (global_counter ==0) {
	      gettimeofday(&first_pkt_time,NULL);
	      gettimeofday(&last_pkt_time,NULL);
	      global_counter=1;
	    }else {
	      gettimeofday(&last_pkt_time,NULL);
	    }
	    total_byte=total_byte+decrypted_tun_frame_len;
	    int sec_elapsed;
	    int usec_elapsed;
	    float total_elapsed;
	    sec_elapsed=last_pkt_time.tv_sec-first_pkt_time.tv_sec;
	    if (last_pkt_time.tv_sec-first_pkt_time.tv_sec) {
	      sec_elapsed=sec_elapsed-1;
	      usec_elapsed = 1000000LL +last_pkt_time.tv_usec -first_pkt_time.tv_usec;
	    }else {
	      usec_elapsed = last_pkt_time.tv_usec -first_pkt_time.tv_usec;
	    }
	    g_pkt_recv++;
	    total_elapsed= sec_elapsed + usec_elapsed/1000000LL;
	    printf("cnt=%d orig=%d, t=%.6f \n",g_pkt_recv, total_byte, total_elapsed);
	  }
	}
	else {
	  // printf("SHA of the frame is INcorrect u=%d fl=%d dcr_fl=%d \n",u, frame_len,decrypted_tun_frame_len);
	}
	// printf("freeeing in decrytion\n");
	free(cipher_tun_frame);
	free(decrypted_tun_frame);
	free(hmac);
      }
  }else {
    //printf("not cool reception\n");
  }
  cnt++;
  if (cnt%20==0)
    printf("r=%d ",g_pkt_recv);

  return 0;
}
/*
  The function is called when a copy of wireless frame transmitted.
*/
int message_injection(const unsigned char * packet,
		      u_int16_t radiotap_len,
		      u_int32_t capture_len)
{
  printf("message_injection() %d %d\n",list_size,g_pkt_send);
  if (!(list_size>0))
    return -1;
  struct ip *ip;
  //struct udp_hdr *udp;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc,seq_no,duration_id,message_len;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len-radiotap_len + sizeof (u8aRadiotapHeader);
  u_int32_t frame_tx_idx=0;
  int tcp_options =TCP_OPTIONS;
  const u_char* mac_address_start;
  const u_char* llc_start_p ;
  u_char * temp_pkt=packet;
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  struct ieee80211_hdr * sc = (struct ieee80211_hdr *)packet;
  duration_id= sc->duration_id;
  mac_address_start=(packet+4);
  seq_no=sc->seq_ctrl;
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(u_int8_t)(mac_hdr_len);
  capture_len -= mac_hdr_len;
  llc_start_p= packet-2;//2 bytes padding by atheros adapter
  llc = (struct llc_hdr *) packet;
  u_char* l= (u_char* )llc;
  printf("llc_start=%02x %02x %02x %02x \n",*l,*(l+1),*(l+2),*(l+3));
  //printf("%d %d\n",ntohs(llc->snap.ether_type),ETHERTYPE_IP);
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection*/
      return -1;
    }
    packet += IP_header_length;
    capture_len -= IP_header_length;

    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    tcp_options=((tcp_h->offx2 >> 4) << 2) -sizeof(struct tcp_hdr);
    //printf("tcp options=%d\n",tcp_options);
    message_offset =  covert_message_offset(ntohl(tcp_h->seq),ntohl(tcp_h->ack),pkt_len);
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    if (ssl_h->ssl_content_type != 0x17) {
      return -1; /*not SSL traffic*/
    }
    printf("ssl v= %02x %02x%02x \n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),
	   *((u_int8_t*)(ssl_h)+2)  );

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);
    const u_char * ssl_hdr_end_p = packet ;
    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <100 ) {
      return -1; /*for now it's mtu=150 bytes*/
    }

    int noms_to_inject;
    noms_to_inject= remaining_bytes/(128+32);
    u_char* frame_to_transmit=NULL;
    u_char* start_frame_to_transmit= malloc(pkt_len);
    memset(start_frame_to_transmit,'\0',sizeof(start_frame_to_transmit));
    frame_to_transmit = start_frame_to_transmit;
    u_char* pu8;

    memcpy(frame_to_transmit, u8aRadiotapHeader,sizeof (u8aRadiotapHeader));
    pu8 = frame_to_transmit;
    pu8[8] = u8aRatesToUse[nRateIndex];
    nRateIndex=nRateIndex+2;
    if (nRateIndex >=sizeof(u8aRatesToUse))
      nRateIndex=0;
    frame_to_transmit += sizeof (u8aRadiotapHeader);
    frame_tx_idx  += sizeof (u8aRadiotapHeader);

    struct ieee80211_hdr * ih = (struct ieee80211_hdr *) u8aIeeeHeader;
    //fc= fc | BIT(6); // for WEP bit to be turned on
    memcpy((u_char*)(&(ih->frame_control)),(u_char*)&fc,2);
    memcpy((u_char*)(&(ih->duration_id)),(u_char*)&duration_id,2);
    memcpy(&(ih->addr1),mac_address_start,MAC_HDR);
    memcpy((u_char*)(&(ih->seq_ctrl)),(u_char*)&seq_no,2);
    //printf("ntohs seq no=%d\n",ntohs(seq_no));
    //printf("htonl seq no=%d\n",htons(seq_no));

    // memcpy(&(ih->addr2),mac_address_start+MAC_HDR,MAC_HDR); //commented for testing purposes

    //memcpy(&(ih->addr3),mac_address_start+(2*MAC_HDR),MAC_HDR);
    if (debug) {
      printf("packet_injection\n");
      printf("addr1:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr1[0],ih->addr1[1],ih->addr1[2],ih->addr1[3],ih->addr1[4], ih->addr1[5]);
      printf("addr2:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr2[0],ih->addr2[1],ih->addr2[2],ih->addr2[3],ih->addr2[4], ih->addr2[5]);
      printf("addr3:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr3[0],ih->addr3[1],ih->addr3[2],ih->addr3[3],ih->addr3[4], ih->addr3[5]);
    }

    memcpy(frame_to_transmit, u8aIeeeHeader, sizeof (u8aIeeeHeader));
    frame_to_transmit += sizeof (u8aIeeeHeader);
    frame_tx_idx += sizeof(u8aIeeeHeader);

    memcpy(frame_to_transmit, llc_start_p, ssl_hdr_end_p - llc_start_p );
    frame_to_transmit += ssl_hdr_end_p-llc_start_p;
    frame_tx_idx += ssl_hdr_end_p-llc_start_p;

    memcpy(frame_to_transmit,ssl_hdr_end_p,message_offset);
    frame_to_transmit +=message_offset;
    packet += message_offset;
    frame_tx_idx += message_offset;
    capture_len -= message_offset;

    message_len=noms_to_inject*(128+32);
    u_char * map;
    map=frame_to_transmit;
    frame_to_transmit +=1;
    packet +=1;
    frame_tx_idx +=1;
    capture_len -=1;

    memcpy(frame_to_transmit,(u_char*)&message_len,SHORT_SIZE);
    frame_to_transmit +=SHORT_SIZE;
    packet += SHORT_SIZE;
    frame_tx_idx += SHORT_SIZE;
    capture_len -= SHORT_SIZE;
    /*
      Number of messages and the total message length to be added here
    */
    u_char c =0;
    int u,r,msg_len=128;
    for(u=0;u<noms_to_inject;u++) {
      u_char *hmac;
      u_char* content;
      r=beg_del_element(&config.tun_f_list,&content, &msg_len,&hmac);
      if (r ==-1)
	break;
      list_size--;
      assert(msg_len>0);
      //printf("msg len=%d %d\n",msg_len,noms_to_inject);

      memcpy(frame_to_transmit,hmac,SHA_SIZE);
      frame_to_transmit +=SHA_SIZE;
      packet += SHA_SIZE;
      frame_tx_idx += SHA_SIZE;
      capture_len -= SHA_SIZE;

      memcpy(frame_to_transmit, content,msg_len);
      frame_to_transmit +=msg_len ;
      packet += msg_len;
      frame_tx_idx += msg_len;
      capture_len -= msg_len;
      if (msg_len ==128){
	c_128++;
      }else if (msg_len ==48){
	c_48++;
	c |= 1 <<u;
      }else{
	printf("TOFIX:msg_len=%d\n",msg_len);
	//exit(1);
      }
      free(content);
      free(hmac);
    }
    memcpy(map,&c,1);


    /*int idx=0;
      for (idx=0;idx<32; idx++)
      printf("%02x ",hmac[idx]);
      printf("\n");*/
    printf("died\n");
    printf("pkt_len=%d cap_len=%d\n",pkt_len,capture_len);
    memcpy(frame_to_transmit,packet,pkt_len-frame_tx_idx);
    frame_to_transmit += (pkt_len-frame_tx_idx);
    capture_len -= (pkt_len-frame_tx_idx);
    //while(1){
    //printf("128=%d, 48=%d\n",c_128,c_48);
    printf("pkt size=%d (pkt_len=%d  ==cap_len=%d)\n",(frame_to_transmit-start_frame_to_transmit),pkt_len,capture_len);
    if (pkt_len ==capture_len) {
      printf("wrong!");
      exit(1);
    }
    transmit_on_wifi(config.wifi_inject_pcap,start_frame_to_transmit, pkt_len); //frame_to_transmit-start_frame_to_transmit);
    //}
    free(start_frame_to_transmit);
  } else {
    printf("injection not happening");
  }
  return 0 ;
}

/*key sharing code starts*/
#define INT_SIZE 4
int key_reception(const unsigned char * packet,
		  u_int16_t radiotap_len,
		  u_int32_t capture_len)
{
  struct ip *ip;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc;
  u_int32_t covert_mesg_size =0;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len;
  int tcp_options =TCP_OPTIONS; //TCP options
  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(mac_hdr_len+8); //TODO: FIXME: Does not work with adding 8 bytes
  capture_len -= (mac_hdr_len);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection eg. gmail*/
      printf("not tcp\n");
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
    //printf("message received bef ssl v= %02x %02x%02x\n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),  *((u_int8_t*)(ssl_h)+2) );
    if (ssl_h->ssl_content_type != 0x17) {
      printf("not 17\n");
      return -1; /*there should be content in the traffic*/
    }

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);

    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <MAX_MTU_SIZE+1) {
      printf("not enough mtu\n");
      return -1; /*for now it's mtu=150 bytes*/
    }
    /* TODO:
       use the key to decrypt the length of message following it
    */
    printf(" key reception: this is it \n");
    packet +=message_offset;
    memcpy((u_char*)&covert_mesg_size,packet,INT_SIZE);
    packet +=INT_SIZE;
    u_char* hmac;
    printf("%02x %02x %02x %02x %02x %02x \n",*packet,*(packet+1), *(packet+2),*(packet+3), *(packet+4),*(packet+5));
    hmac= malloc(SHA_SIZE);
    memset(hmac,0,SHA_SIZE);
    memcpy(hmac,packet,SHA_SIZE);
    packet +=SHA_SIZE;
    u_char* covert_message;
    printf("just before mallocs\n");
    covert_message = malloc(covert_mesg_size);
    memset(covert_message,0,covert_mesg_size);
    memcpy(covert_message,packet,covert_mesg_size);
    char k[]="abhinav";
    u_char * sha_256;
    printf("getting the sha");
    sha_256 = HMAC(EVP_sha256(), k, strlen(k)+1, covert_message, (const int)covert_mesg_size, NULL, NULL);
    if (memcmp(hmac,sha_256,SHA_SIZE)) {
      printf("the sha of the frame do not match! hence not the 'key' frame BAD!!!\n");
      free(hmac);
      free(covert_message);
      return -1;
    } else {
      printf("This frame has the key lengths needed. AWESOME!\n");
    }
    int S_T= sizeof(size_t);
    memcpy((u_char*)&config.rsa_ivl,covert_message,S_T);
    covert_message +=S_T;
    memcpy((u_char*)&config.rsa_ekl,covert_message,S_T);
    covert_message +=S_T;
    memcpy((u_char*)&config.encr_shared_key_len,covert_message, S_T);
    covert_message +=S_T;
    config.rsa_iv = malloc(config.rsa_ivl);
    config.rsa_ek = malloc(config.rsa_ekl);
    config.encr_shared_key = malloc(config.encr_shared_key_len);
    memcpy(config.rsa_iv,covert_message, config.rsa_ivl);
    covert_message +=config.rsa_ivl;
    memcpy(config.rsa_ek,covert_message,config.rsa_ekl);
    covert_message +=config.rsa_ekl;
    memcpy(config.encr_shared_key,covert_message, config.encr_shared_key_len);

    if (debug) {
      char* b64String = base64Encode(config.encr_shared_key, config.encr_shared_key_len);
      printf("Encrypted message: %s\n", b64String);
    }

    if((config.decr_shared_key_len = rsa_decrypt(config.encr_shared_key, (size_t)config.encr_shared_key_len, \
						 config.rsa_ek, (size_t) config.rsa_ekl, config.rsa_iv, (size_t) config.rsa_ivl, \
						 (u_char**)&config.decr_shared_key, config.rcv_priv_key, &config.rsa_de )) == -1) {
      fprintf(stderr, "Decryption failed\n");
      return -1;
    }

    printf("decr: :%s\n", config.decr_shared_key);
    memcpy(config.shared_key,config.encr_shared_key,config.encr_shared_key_len);
    config.shared_key_len =config.encr_shared_key_len;
    if (aes_init(config.shared_key, config.shared_key_len, (unsigned char *)&config.salt, &config.en, &config.de)) {
      printf("Couldn't initialize AES cipher\n");
      return -1;
    }else {
      printf("aes in init success in client \n");
    }
    config.session_key_exchanged=1;
    free(hmac);
    free(covert_message);
  }
  return 0;
}
/*
  Injects the shared encrypted session key
*/
int key_injection(const unsigned char * packet,
		  u_int16_t radiotap_len,
		  u_int32_t capture_len)
{
  printf("key_injection() %d\n",list_size);
  struct ip *ip;
  //struct udp_hdr *udp;
  struct llc_hdr *llc;
  struct tcp_hdr *tcp_h;
  struct ssl_hdr *ssl_h;
  u_int16_t IP_header_length,fc,seq_no,duration_id;
  u_int32_t message_len;
  u_int32_t message_offset;
  u_int32_t pkt_len=capture_len-4;
  int tcp_options =TCP_OPTIONS;
  const u_char* mac_address_start;
  const u_char* llc_start_p ;

  packet += radiotap_len;
  capture_len -= radiotap_len;
  fc = EXTRACT_LE_16BITS(packet);
  struct ieee80211_hdr * sc = (struct ieee80211_hdr *)packet;
  duration_id= sc->duration_id;
  mac_address_start=(packet+4);
  seq_no=sc->seq_ctrl;
  int mac_hdr_len  = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
  if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
    mac_hdr_len += 2;
  packet +=(mac_hdr_len+8);
  llc_start_p= packet-10;
  capture_len -= (mac_hdr_len+8);
  llc = (struct llc_hdr *) packet;
  if (ntohs(llc->snap.ether_type) == ETHERTYPE_IP) {
    packet +=sizeof(struct llc_hdr);
    capture_len -= sizeof(struct llc_hdr);
    ip = (struct ip*)packet;
    IP_header_length = ip->ip_hl * 4;
    if (ip->ip_p != IPPROTO_TCP) { /*Has to be a TCP connection*/
      return -1;
    }
    packet += IP_header_length;
    capture_len -= IP_header_length;

    tcp_h = (struct tcp_hdr *)packet;
    //printf("sport number = %d, seq no. = %u,ack no. = %u
    //\n",ntohs(tcp_h->dport),ntohl(tcp_h->seq),ntohl(tcp_h->ack));
    tcp_options=((tcp_h->offx2 >> 4) << 2) -sizeof(struct tcp_hdr);
    message_offset =  covert_message_offset(ntohl(tcp_h->seq),ntohl(tcp_h->ack),pkt_len);
    packet +=sizeof(struct tcp_hdr);
    capture_len -= sizeof(struct tcp_hdr);

    packet += tcp_options;
    capture_len -= tcp_options;
    ssl_h = (struct ssl_hdr *)packet;
    if (ssl_h->ssl_content_type != 0x17) {
      return -1; /*not SSL traffic*/
    }
    printf("ssl v= %02x %02x%02x \n", *((u_int8_t*)(ssl_h)), *((u_int8_t*)(ssl_h)+1),
	   *((u_int8_t*)(ssl_h)+2)  );

    packet += sizeof(struct ssl_hdr);
    capture_len -= sizeof(struct ssl_hdr);
    const u_char * ssl_hdr_end_p = packet ;
    int remaining_bytes=capture_len-(CRC_BYTES_LEN+ H_MAC_BYTES_LEN+ MSG_BYTES_LEN+ message_offset);
    if (remaining_bytes <MAX_MTU_SIZE+1) {
      return -1; /*for now it's mtu=150 bytes*/
    }
    u_char *hmac;
    u_char* frame_to_transmit=NULL;
    u_char* start_frame_to_transmit= malloc(pkt_len);
    memset(start_frame_to_transmit,'\0',sizeof(start_frame_to_transmit));
    frame_to_transmit = start_frame_to_transmit;

    memcpy(frame_to_transmit, u8aRadiotapHeader,sizeof (u8aRadiotapHeader));
    frame_to_transmit += sizeof (u8aRadiotapHeader);

    struct ieee80211_hdr * ih = (struct ieee80211_hdr *) u8aIeeeHeader;
    //fc= fc | BIT(6); // for WEP bit to be turned on
    memcpy((u_char*)(&(ih->frame_control)),(u_char*)&fc,2);
    memcpy((u_char*)(&(ih->duration_id)),(u_char*)&duration_id,2);
    memcpy(&(ih->addr1),mac_address_start,MAC_HDR);
    memcpy((u_char*)(&(ih->seq_ctrl)),(u_char*)&seq_no,2);
    // memcpy(&(ih->addr2),mac_address_start+MAC_HDR,MAC_HDR); //commented for testing purposes

    //memcpy(&(ih->addr3),mac_address_start+(2*MAC_HDR),MAC_HDR);
    if (debug) {
      printf("packet_injection\n");
      printf("addr1:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr1[0],ih->addr1[1],ih->addr1[2],ih->addr1[3],ih->addr1[4], ih->addr1[5]);
      printf("addr2:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr2[0],ih->addr2[1],ih->addr2[2],ih->addr2[3],ih->addr2[4], ih->addr2[5]);
      printf("addr3:%02x:%2x:%02x:%02x:%02x:%02x\n",ih->addr3[0],ih->addr3[1],ih->addr3[2],ih->addr3[3],ih->addr3[4], ih->addr3[5]);
    }

    memcpy(frame_to_transmit, u8aIeeeHeader, sizeof (u8aIeeeHeader));
    frame_to_transmit += sizeof (u8aIeeeHeader);

    memcpy(frame_to_transmit, llc_start_p, ssl_hdr_end_p - llc_start_p );
    frame_to_transmit += ssl_hdr_end_p-llc_start_p;

    memcpy(frame_to_transmit,ssl_hdr_end_p,message_offset);
    frame_to_transmit +=message_offset;
    packet += message_offset;
    capture_len -= message_offset;
    u_char* content;
    message_len = 12+ config.rsa_ekl+config.rsa_ivl+config.encr_shared_key_len;
    content = malloc(message_len);
    memset(content,'\0',message_len);

    memcpy(frame_to_transmit,(u_char*)&message_len,INT_SIZE);
    frame_to_transmit +=INT_SIZE;
    packet += INT_SIZE;
    capture_len -= INT_SIZE;
    int S_T = 4;
    memcpy(content,(u_char*)&config.rsa_ivl, S_T);
    content +=S_T;
    memcpy(content,(u_char*)&config.rsa_ekl, S_T);
    content +=S_T;
    memcpy(content,(u_char*)&config.encr_shared_key_len, S_T);
    content +=S_T;
    memcpy(content,config.rsa_iv, config.rsa_ivl);
    content +=config.rsa_ivl;
    memcpy(content,config.rsa_ek, config.rsa_ekl);
    content +=config.rsa_ekl;
    memcpy(content,(u_char*)config.encr_shared_key, config.encr_shared_key_len);
    content += config.encr_shared_key_len;

    char k[]="abhinav";
    hmac = HMAC(EVP_sha256(), k, strlen(k)+1, content, (const int)message_len, NULL, NULL);

    memcpy(frame_to_transmit,hmac,SHA_SIZE);
    printf("fr_to_tx: %02x %02x %02x %02x \n",*(frame_to_transmit),*(frame_to_transmit+1),*(frame_to_transmit+2), *(frame_to_transmit+3));

    frame_to_transmit +=SHA_SIZE;
    packet += SHA_SIZE;
    capture_len -= SHA_SIZE;

    memcpy(frame_to_transmit, content, message_len);
    frame_to_transmit +=message_len;
    packet += message_len;
    capture_len -= message_len;

    memcpy(frame_to_transmit,packet,pkt_len-capture_len);
    frame_to_transmit += (pkt_len-capture_len);
    capture_len -= (pkt_len-capture_len);
    while(1){
      printf("rEY transmit pkt size diff=%d pkt_len%u cap_len=%d\n",(frame_to_transmit-start_frame_to_transmit),pkt_len,capture_len);
      printf("msg_len=%d ivl=%d, ekl=%d ,encr=%d \n",message_len,config.rsa_ivl,config.rsa_ekl,config.encr_shared_key_len);
      int idx=0;
      printf("sha\n");
      for (idx=0;idx<SHA_SIZE;idx++)
	printf("%02x ",hmac[idx]);
      printf("cov mesg\n");
      for (idx=0;idx<message_len;idx++)
	printf("%02x ",content[idx]);
      transmit_on_wifi(config.wifi_inject_pcap,start_frame_to_transmit, pkt_len); //frame_to_transmit-start_frame_to_transmit);
    }
    free(start_frame_to_transmit);
    free(content);
    printf("session key is exchanged \n");
    config.session_key_exchanged=1;
  }
  return 0 ;
}

/*key sharing code ends*/
int packet_parse(const unsigned char *packet,
		 struct timeval ts,
		 unsigned int capture_len)
{
  u_int16_t radiotap_len=0;
  struct ieee80211_radiotap_header *hdr;
  hdr = (struct ieee80211_radiotap_header *)packet;
  radiotap_len = pletohs(&hdr->it_len);
  if (capture_len <1400) { /*messages are contained in large frames only*/
    return -1;
  }
  if (1 /*config.session_key_exchanged*/) {
    if (radiotap_len ==13) {
      printf("message injection caplen->%d rad=%d\n",capture_len, radiotap_len);
      /*
	int k=0;
	modulo++;
	k=modulo%10;
	if (modulo%3==0 || modulo%5==0 || modulo%7==0){
	} else{
      */
      message_injection(packet, radiotap_len, capture_len);
      //	}
    }
    else { /*need frames that are sent out through device */
      //printf("# no 14 %d %d\n",capture_len,radiotap_len);//reception caplen->%d\n",capture_len);
      //message_reception(packet, radiotap_len, capture_len); //to be enabled at receiver side
    }
  }else {
    if (radiotap_len ==14 ) {
      printf("key injection caplen->%d\n",capture_len);
      key_injection(packet, radiotap_len, capture_len);
    }
    else { /*need frames that are sent out through device */
      printf("key recv caplen->%d %d\n",capture_len, radiotap_len);
      //key_reception(packet, radiotap_len, capture_len); //to be enabled at receiver side
    }
  }

  return 0;
}

int check_tun_frame_content(u_char* orig_covert_frame,
			    int tun_frame_cap_len)
{
  struct ip *ip;
  struct udp_hdr *udp;

  ip = (struct ip *)orig_covert_frame;
  if (tun_frame_cap_len < ip->ip_hl*4 ) { /* didn't capture the full IP header including options */
    printf("IP header with options\n");
    return -1;
  }
  int src_addr =0;
  src_addr = inet_addr("10.0.0.12");
  if (ip->ip_p == IPPROTO_UDP) {
    // printf("UDP packet on TUN interface\n");
    /* Skip over the IP header to get to the UDP header. */
    orig_covert_frame += ip->ip_hl*4;
    udp = (struct udp_hdr*)orig_covert_frame;
    /* printf("UDP src_port=%d dst_port=%d length=%d\n",
       ntohs(udp->uh_sport),
       ntohs(udp->uh_dport),
       ntohs(udp->uh_ulen));      */
  }
  else if (ip->ip_p == IPPROTO_TCP) {
    printf("TCP packet %d\n",ip->ip_p);
  }
  else {
    printf("none of the protocol; ICMP mostly ?\n");
  }
  int temp = ip->ip_src.s_addr;
  printf("src=%x \n",ip->ip_src.s_addr);
  printf("dst=%x \n",ip->ip_dst.s_addr);
  printf("src_addr=%x  %x\n",src_addr,temp);
  if (temp==src_addr) {
    printf("bad\n");
    return -1;
  }
  else {
    printf("good\n");
    return 0;
  }
}

int rsa_client_priv_key()
{

  RSA *rsa_privkey = NULL;
  FILE*rsa_privkey_file;
  config.rcv_priv_key = EVP_PKEY_new();
  rsa_privkey_file = fopen("./keys/privkey.pem", "rb");

  if (!rsa_privkey_file) {
    fprintf(stderr, "Error loading PEM RSA Private Key File.\n");
    return -1;
  }

  if (!PEM_read_RSAPrivateKey(rsa_privkey_file, &rsa_privkey, NULL, NULL)) {
    fprintf(stderr, "Error loading RSA Private Key File.\n");
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!EVP_PKEY_assign_RSA(config.rcv_priv_key, rsa_privkey)) {
    fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
    return -1;
  }
  return 0;
}

int rsa_server_pub_key()
{
  RSA *rsa_pubkey = NULL;
  FILE* rsa_pubkey_file;
  config.snd_pub_key  = EVP_PKEY_new();
  rsa_pubkey_file = fopen("./keys/publickey.pub", "rb");

  if (!rsa_pubkey_file) {
    fprintf(stderr, "Error loading PEM RSA Public Key File.\n");
    return -1;
  }

  if (!PEM_read_RSA_PUBKEY(rsa_pubkey_file, &rsa_pubkey, NULL, NULL))
    {
      fprintf(stderr, "Error loading RSA Public Key File.\n");
      ERR_print_errors_fp(stderr);
      return -1;
    }

  if (!EVP_PKEY_assign_RSA(config.snd_pub_key, rsa_pubkey))
    {
      fprintf(stderr, "EVP_PKEY_assign_RSA: failed.\n");
      return -1;
    }

  return 0;
}


int main(int argc, char** argv)
{
  u_char buf[PACKET_SIZE];
  char ifname[IF_NAMESIZE];
  int tun_frame_cap_len;

  const u_char * radiotap_packet;
  struct pcap_pkthdr header;

  char * mon_read_ifname="phy0";
  char * mon_inject_ifname="phy2";

  fd_set rd_set;

  int key_msg_len;
  u_char* key_msg;

  //  key_msg= "This is the initial sharing key";
  //  key_msg_len= strlen("This is the initial sharing key");
  config.shared_key= (u_char*)"20142343243243935943uireuw943uihflsdh3otu4tjksdfj43p9tufsdfjp9943u50943";
  u_char k[]="20142343243243935943uireuw943uihflsdh3otu4tjksdfj43p9tufsdfjp9943u50943";
  config.shared_key_len= sizeof(k);

  memcpy(config.salt, (u_int32_t[]) {12345, 54321}, sizeof config.salt);
  config.tun_f_list =NULL;

  extern char *optarg;
  extern int optind;
  int c, check=0, err=0;
  int tflag=0, readmon_flag=0,injectmon_flag=0,mode_flag=0;
  char *tun_ifname = "tun2";
  char mode;
  static char usage[] = "usage: %s [-d] -r read_interface -i inject_inteface -m mode [-s tun_ifname] \n";

  while ((c = getopt(argc, argv, "dtr:i:m:")) != -1)
    switch (c) {
    case 'd':
      debug = 1;
      break;
    case 't':
      tflag = 1;
      tun_ifname = *optarg;
      break;
    case 'r':
      readmon_flag = 1;
      mon_read_ifname = optarg;
      break;
    case 'i':
      injectmon_flag = 1;
      mon_inject_ifname = optarg;
      break;
    case 'm':
      mode_flag = 1;
      mode = *optarg;
      printf(" %c\n",mode);
      if (mode =='c' || mode =='s') {
	printf("Working mode %c\n",mode);
      }else {
	printf("Use (c)lient or (s)erver mode\n");
	exit(-1);
      }
      break;
    case '?':
      err = 1;
      break;
    }

  if (readmon_flag == 0) {/* -r is mandatory */
    fprintf(stderr, "%s: missing -r option\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if(injectmon_flag==0) {
    fprintf(stderr, "%s: missing -i option\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if(mode_flag==0) {
    fprintf(stderr, "%s: missing -m option\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if ((optind+1) < argc) {
    /* need at least one argument (change +1 to +2 for two, etc. as needeed) */
    printf("optind = %d, argc=%d\n", optind, argc);
    fprintf(stderr, "%s: missing name\n", argv[0]);
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  } else if (err) {
    fprintf(stderr, usage, argv[0]);
    exit(-1);
  }


  config.wifi_inject_pcap= pcap_radiotap_handler(mon_inject_ifname);

  if (pcap_setnonblock(config.wifi_inject_pcap, 1, errbuf) == -1) {
    fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    exit(-1);
  }
  if (pcap_set_snaplen(config.wifi_inject_pcap, 65535) ==-1) {
    fprintf(stderr, "can't set inject snaplen %s\n",errbuf);
  }

  config.wifi_read_pcap= pcap_radiotap_handler(mon_read_ifname);

  if (config.wifi_read_pcap ==NULL) {
    fprintf(stderr,"pcap file descriptor not avaiable:%s\n",errbuf);
    exit(-1);
  }
  if (pcap_set_snaplen(config.wifi_read_pcap, 65535) ==-1) {
    fprintf(stderr, "can't set read snaplen %s\n",errbuf);
  }

  if (pcap_setnonblock(config.wifi_read_pcap, 1, errbuf) == -1) {
    fprintf(stderr, "pcap_setnonblock failed: %s\n", errbuf);
    exit(-1);
  }

  config.pcap_read_fd = pcap_get_selectable_fd(config.wifi_read_pcap);

  strcpy(ifname,tun_ifname);
  if ((config.tun_fd= tun_allocation(ifname)) < 0) {
    fprintf(stderr, "tunnel interface allocation failed\n");
    exit(-1);
  }

  //RSA assymetric key cipher
  /*
    if ( mode =='s') {
    rsa_encrypt_init(&config.rsa_en);
    rsa_server_pub_key();
    config.shared_key= key_msg ; //(u_char*)"20142343243243935943uireuw943uihflsdh3otu4tjksdfj43p9tufsdfjp9943u50943";
    //u_char k[]="20142343243243935943uireuw943uihflsdh3otu4tjksdfj43p9tufsdfjp9943u50943";
    config.shared_key_len= key_msg_len; //sizeof(k);

    if((config.encr_shared_key_len = rsa_encrypt((const u_char*)key_msg, key_msg_len+1, &config.encr_shared_key, \
    &config.rsa_ek, &config.rsa_ekl, &config.rsa_iv, &config.rsa_ivl, \
    config.snd_pub_key, &config.rsa_en))== -1) {
    fprintf(stderr, "Encryption failed\n");
    return -1;
    }
    printf(" ekl=%d ivl=%d config.encr_shared_key_len=%d\n",config.rsa_ekl,config.rsa_ivl,config.encr_shared_key_len);

    printf("The message is now encrypted\n");
    // Print the encrypted message as a base64 string
    if (debug) {
    char* b64String = base64Encode(config.encr_shared_key, config.encr_shared_key_len);
    printf("Encrypted message: %s\n", b64String);
    }
    if (aes_init(config.shared_key, config.shared_key_len, (unsigned char *)&config.salt, &config.en, &config.de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
    }
    } else if (mode =='c') {
    printf("in c mode \n");
    rsa_decrypt_init(&config.rsa_de);
    rsa_client_priv_key();
    }
  */
  if (aes_init(config.shared_key, config.shared_key_len, (unsigned char *)&config.salt, &config.en, &config.de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }else {
    printf("aes in init success in client \n");
  }



  printf("allocted tunnel interface %s\n", tun_ifname);

  int maxfd = (config.tun_fd > config.pcap_read_fd)?config.tun_fd:config.pcap_read_fd;
  while(1)
    {
      int ret;

      FD_ZERO(&rd_set);
      FD_SET(config.tun_fd, &rd_set);
      FD_SET(config.pcap_read_fd, &rd_set);
      ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

      if (ret < 0 && errno == EINTR)
	continue;
      if (ret < 0) {
	perror("select()");
	exit(1);
      }
      if(FD_ISSET(config.tun_fd, &rd_set)) {
	memset(buf,0,sizeof(buf));
	if ((tun_frame_cap_len = read(config.tun_fd, buf, sizeof(buf))) < 0) {
	  perror("read() on tun file descriptor");
	  close(config.tun_fd);
	  exit(1);
	}
	check=check_tun_frame_content(buf, tun_frame_cap_len);
	if (check==0 /*&& config.session_key_exchanged*/) {
	  end_add_element(&config.tun_f_list, buf ,tun_frame_cap_len);
	  list_size++;
	  g_pkt_send++;
	} else {
	  printf("exchange status: %d\n",config.session_key_exchanged);
	}
	printf("%02x %02x %02x %02x \n",*buf, *(buf+1), *(buf+2),*(buf+3));
	printf("read %d bytes from tunnel interface %s.\n-----\n", tun_frame_cap_len, tun_ifname);
      }
      if(FD_ISSET(config.pcap_read_fd, &rd_set)) {
	radiotap_packet = pcap_next(config.wifi_read_pcap, &header);
	if (header.caplen>1700) {
	  //if (header.caplen!=header.len) {
	  printf(" %d %d ",header.caplen,header.len);
	  return -1;}

	packet_parse(radiotap_packet, header.ts, header.caplen);
      }
    }
  return 0;
}
