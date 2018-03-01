/* 
 * EL7373 (Spring 2014) High Performance Switches and Routers
 *
 * Lab 1 - IP Lookup Algorithms
 *
 * test_pcap_offline.c
 *
 * TA: Kuan-yin Chen (cgi0911@gmail.com)
 *
 * Description:
 *  1. The program first reads filename from command line (argv[1]).
 *  2. It then opens a PCAP descriptor using the input filename, 
 *     e.g. "trace.dump".
 *  3. After that, the program sniffs packets from the dump file.
 *  4. Upon receiving one packet, the program prints out the source and 
 *     destination IP addresses.
 *
 * Notes:
 *  1. Code is adapted from Martin Casado's pcap tutorial.
 *     Original code available at: 
 *     http://yuba.stanford.edu/~casado/pcap/section1.html
 *
 *  2. To compile the code, type in the command line:
 *     > g++ test_pcap_online.c -o a.out -lpcap
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
    char    *src_addr;

    eth_hdr =   (struct sniff_ethernet *)(pktdata);
    ip_hdr =    (struct sniff_ip *)(pktdata + SIZE_ETHERNET);

    pkt_cnt ++;

    src_addr = inet_ntoa(ip_hdr->ip_src);
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
     * Part 1: Open the dump file for reading,
     *         then sniff packets from it.
     * -------------------------------------------------- */

    /* argc < 2 means no filename is input from the command line. */
    if( argc < 2 ){
        printf("You forgot to enter dump file name!\n");
        exit(1);
    }

    /* 
     * open the file for sniffing.
     *
     * pcap_t *pcap_open_offline( const char *fname, char *errbuf ) 
     *
     * fname - Filename of the dump file
     * errbuf  - if something happens, place error string here
     */

    descr = pcap_open_offline(argv[1], errbuf);
    
    /* pcap_compile allows only IPv4 tcp and udp packets to pass! */
    pcap_compile(descr, &fp, "tcp or udp and not ipv6", 0, 0);

    /* error check */
    if(descr == NULL)
    {
        printf("pcap_open_offline(): %s\n",errbuf);
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
}
