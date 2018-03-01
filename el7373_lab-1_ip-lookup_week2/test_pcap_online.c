/* 
 * EL7373 (Spring 2014) High Performance Switches and Routers
 *
 * Lab 1 - IP Lookup Algorithms
 *
 * test_pcap_online.c
 *
 * TA: Kuan-yin Chen (cgi0911@gmail.com)
 *
 * Description:
 *  1. The program first looks for an interface (eth0 for most cases).
 *  2. It then lists the network IP and mask associated with that interface.
 *  3. After that, the program sniffs on the network interface.
 *  4. Upon receiving one packet, the program prints out the dest IP.
 *
 * Notes:
 *  1. Code is adapted from Martin Casado's pcap tutorial.
 *     Original code available at: 
 *     http://yuba.stanford.edu/~casado/pcap/section1.html
 *
 *  2. To compile the code, type in the command line:
 *     > gcc test_pcap_online.c -o a.out -lpcap
 *
 *  3. To run the code, you might need to sudo:
 *     > sudo ./a.out
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHER_ADDR_LEN  6   /* MAC address is 6 bytes */
#define SIZE_ETHERNET 14    /* Ethernet header is 14 bytes */

/* struct for Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* struct for IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
#define IP_RF 0x8000        /* reserved fragment flag */
#define IP_DF 0x4000        /* dont fragment flag */
#define IP_MF 0x2000        /* more fragments flag */
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr      ip_src;
    struct in_addr      ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

const struct sniff_ethernet     *eth_hdr;
const struct sniff_ip           *ip_hdr;
unsigned long int               pkt_cnt = 0;

void my_callback(u_char *user, 
                 const struct pcap_pkthdr *pkthdr, 
                 const u_char *pktdata)
{
    char    *dst_addr;

    eth_hdr =   (struct sniff_ethernet *)(pktdata);
    ip_hdr =    (struct sniff_ip *)(pktdata + SIZE_ETHERNET);

    pkt_cnt ++;
    dst_addr = inet_ntoa(ip_hdr->ip_dst);

    printf("Packet #%-10ld - dest ip %s\n", pkt_cnt, dst_addr);

}


int main(int argc, char **argv)
{
    char    *dev;       /* name of the device to use */ 
    char    *net;       /* dot notation of the network address */
    char    *mask;      /* dot notation of the network mask    */
    int     ret;        /* return code */
    char    errbuf[PCAP_ERRBUF_SIZE];   /* Error message buffer */
    bpf_u_int32     netp;   /* ip          */
    bpf_u_int32     maskp;  /* subnet mask */
    struct in_addr  addr;   /* in_addr is a struct that stores IPv4 addr */
    pcap_t  *descr;     /* pcap descriptor */
    bpf_program fp;     /* berkeley packet filter. will explain later. g++ only! */


    /* --------------------------------------------------
     * Part 1: Detect your computer's network interface,
     *         network address and network mask.
     * -------------------------------------------------- */

    /* ask pcap to find a valid device for use to sniff on */
    dev = pcap_lookupdev(errbuf);

    /* error checking. quit if no device available */
    if(dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    /* print out device name */
    printf("DEV: %s\n", dev);

    /* ask pcap for the network address and mask of the device */
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if(ret == -1)   /* if lookupnet failed... */
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    /* convert the network address (32-bit unsigned int)
     * to human readable form (dot notation) */
    addr.s_addr = netp;
    net = inet_ntoa(addr);  /* here's the conversion function */

    if(net == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("NET: %s\n",net);

    /* do the same as above for the device's mask */
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);

    if(mask == NULL)
    {
        perror("inet_ntoa");
        exit(1);
    }

    printf("MASK: %s\n",mask);


    /* --------------------------------------------------
     * Part 2: Sniff packets from the detected device.
     * -------------------------------------------------- */

    /* open the device for sniffing.

       pcap_t *pcap_open_live( char *device,int snaplen, 
                               int  prmisc,
                               int  to_ms,
                               char *ebuf)

       snaplen - maximum size of packets to capture in bytes
       promisc - set card in promiscuous mode?
       to_ms   - time to wait for packets in miliseconds before read times out
                 set to -1 if you want to sniff forever
       errbuf  - if something happens, place error string here

       Note if you change "prmisc" param to anything other than zero, you will
       get all packets your device sees, whether they are intendeed for you or
       not!! Be sure you know the rules of the network you are running on
       before you set your card in promiscuous mode!!     */

    descr = pcap_open_live(dev, BUFSIZ, 0, 10000, errbuf);

    /* pcap_compile allows only IPv4 tcp and udp packets to pass! */
    pcap_compile(descr, &fp, "tcp or udp and not ipv6", 0, 0);

    if(descr == NULL)
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    /* Here is the packet sniffing loop. It loops and receives packets
     * until timeout or packet count reached. Every time it receives a 
     * packet, it will call a user-defined callback function, which 
     * typically contains packet processing functionality.
     *
     * int pcap_loop(pcap_t *descr,
     *               int    cnt,
     *               pcap_handler callback,
     *               u_char *user)
     *
     * descr - pcap descriptor
     * cnt   - packet count
     * callback - function called when a packet is received
     * user  - specifies the first argument to pass into the callback routine
     */

    pcap_loop(descr, -1, my_callback, NULL);

    printf("Done with packet processing!\n");
    return 0;
       



    return 0;
}
