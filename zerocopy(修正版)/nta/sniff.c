/*
 * 	sniff.c
 * 
 * 2010 Copyright (c) Ricardo Chen <ricardo.chen@semptianc.om>
 * All rights reserved.
 * 
 * 2006 Copyright (c) Evgeniy Polyakov <johnpol@2ka.mipt.ru>
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <linux/types.h>
#include <net/if.h>


#include "control.h"

unsigned long g_count, g_num_read, g_num_write;


 void zc_usage(char *p)
{
	fprintf(stderr, "Usage: %s -f sniffer_file -c nr_cpus -i ifname\n", p);
}


#define NIPE(eth) \
	(eth)->ether_shost[0], \
	(eth)->ether_shost[1], \
	(eth)->ether_shost[2], \
	(eth)->ether_shost[3], \
	(eth)->ether_shost[4], \
	(eth)->ether_shost[5], \
	(eth)->ether_dhost[0], \
	(eth)->ether_dhost[1], \
	(eth)->ether_dhost[2], \
	(eth)->ether_dhost[3], \
	(eth)->ether_dhost[4], \
	(eth)->ether_dhost[5]

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]


#define dump_skb(s, p, l) \
do {\
    int i;\
    printf("\n%s %s packet: \n", __FUNCTION__, s);\
    for(i=0; i<l; i++) {\
		printf("%02x ", p[i]&0xff); \
        if((i+1)%8==0) {\
		if((i+1)%16==0) \
            		printf( "\n");\
        	else\
            		printf( "\t");\
        	}\
    } \
    printf( "\n"); \
}while(0)

void  zc_handle(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *bytes)
{
	struct ether_header *eth;
	struct iphdr *iph;
	struct tcphdr *th;
	const unsigned char *p = bytes;
	__u16 sport, dport;

	eth = (struct ether_header*)p;

	g_count ++;
	dump_skb("test", bytes, h->caplen);
	printf("\npacket:%d, snaplen:%d\n", g_count, h->caplen);

#if 1
	if (eth->ether_type == ntohs(ETHERTYPE_IP)){
		iph = (struct iphdr *)(eth + 1);
		sport = ((__u16 *)(((void *)iph) + (iph->ihl<<2)))[0];
		dport = ((__u16 *)(((void *)iph) + (iph->ihl<<2)))[1];

		printf("packet length: %d  %u.%u.%u.%u -> %u.%u.%u.%u,  protocal: l3 %x, l4 %u\n",
				h->len, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), ntohs(eth->ether_type), iph->protocol);
		printf("==================================================================\n");
            
		if(iph->protocol == IPPROTO_TCP) {
			//printf(" port %u -> %u", ntohs(sport), ntohs(dport));
			th = (struct tcphdr *)(((void *)iph) + (iph->ihl<<2));
			//printf("seq: %u, ack: %u, ", ntohl(th->seq), ntohl(th->ack_seq));
		}
		if(iph->protocol == IPPROTO_UDP) {
			//printf(" port %u -> %u", ntohs(sport), ntohs(dport));
		}
	}
	//printf("\n");
#endif
	return;
}



int main(int argc, char *argv[])
{
	int ch;
	unsigned int i, nr_cpus;
	char *ctl_file, *ifname;
	int dev_index;
	struct pollfd *pfd;
	struct zc_user_control *ctl;
	zc_t* zc_ctl;
	char errbuf[ERR_BUF_SIZE];

	int my_sniifer_id = 0;


	ctl_file = ifname = NULL;
	nr_cpus = NTA_NR_CPUS;
	g_count = 0;
	while ((ch = getopt(argc, argv, "f:i:c:h") != -1) {
		switch (ch) {
			case 'c':
				nr_cpus = atoi(optarg);
				if(nr_cpus > NTA_NR_CPUS)
				{
				      	zc_usage(argv[0]);
					printf("cpu numbers could not be more than %d!\n", NTA_NR_CPUS);
				    	return 0;
				}
				break;
			case 'i':
				ifname = optarg;
				break;
			case 'f':
				ctl_file = optarg;
				break;
			case 'h':
			default:
				zc_usage(argv[0]);
				return 0;
		}
	}

	if (nr_cpus > 1024) {
		fprintf(stderr, "Wrong number of CPUs %d.\n", nr_cpus);
		zc_usage(argv[0]);
		return -1;
	}

	zc_ctl = zc_open_live("eth0", 128, errbuf);
	if(!zc_ctl)
	{
		printf("zc_open_live errors:%s\n", errbuf);
		return 0;
	}

       zc_loop(zc_ctl,0,  zc_handle,NULL);

	zc_destroy(zc_ctl);

	printf("current count: g_count %lu g_num_write %lu g_num_read %lu\n",
		   g_count, g_num_write, g_num_read);
	return 0;
}
