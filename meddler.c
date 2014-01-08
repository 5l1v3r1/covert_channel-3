#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <stdint.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#define PACKET_SIZE 1515

struct UDP_hdr {
  u_int16_t uh_sport;       /* source port */
  u_int16_t uh_dport;       /* destination port */
  u_int16_t uh_ulen;        /* datagram length */
  u_int16_t uh_sum;         /* datagram checksum */
};

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


int main()
{
  char buf[PACKET_SIZE];
  char ifname[IFNAMSIZ];
  int capture_len, fd;
  struct ip *ip;
  struct UDP_hdr *udp;
  //    strcpy(ifname, "tun%d");
  strcpy(ifname, "tun2");
  if ((fd = tun_alloc(ifname)) < 0) {
    fprintf(stderr, "tunnel interface allocation failed\n");
        exit(1);
  }
  printf("allocted tunnel interface %s\n", ifname);
  for (;;) {
    memset(buf,sizeof(buf), 0);
    if ((capture_len = read(fd, buf, sizeof(buf))) < 0) {
      perror("read() on tun file descriptor");
      close(fd);
      exit(1);
    }   
    u_char *packet= malloc(capture_len);
    memset(packet, capture_len, 0);
    memcpy(packet, buf, capture_len);
    ip = (struct ip *) packet ;
    struct ip_packet * p= (struct ip_packet*) packet;
    if (capture_len < ip->ip_hl*4 )
      { /* didn't capture the full IP header including options */
	printf("IP header with options\n");
	return;
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
	packet += ip->ip_hl*4;
	udp = (struct UDP_hdr*)packet;
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
      printf("not TCP/UDP \n");
      return;
    }
    printf("read %d bytes from tunnel interface %s.\n-----\n", capture_len, ifname);
	
    

  }    
  return 0;
}
