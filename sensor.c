/*
** Copyright (C) 2014 Equilibrium Networks, Incorporated

** This program is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.

** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.

** You should have received a copy of the GNU General Public License
** along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

/* sensor.c
 *   @author gt, asd
 *   Version 0.9
 * based on:
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 * "sniffer.c" is distributed under these terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *	products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *	terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *	notice at the top of this source file, this list of conditions and the
 *	following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *	products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 *
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 *
 ****************************************************************************
 *
 * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
 * mail list when someone asked, "How do I get the length of the TCP
 * payload?" Guy Harris' slightly snipped response (edited by him to
 * speak of the IPv4 header length and TCP data offset without referring
 * to bitfield structure members) is reproduced below:
 *
 * The Ethernet size is always 14 bytes.
 *
 * <snip>...</snip>
 *
 * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if
 * you're using structures, you must use structures where the members
 * always have the same size on all platforms, because the sizes of the
 * fields in Ethernet - and IP, and TCP, and... - headers are defined by
 * the protocol specification, not by the way a particular platform's C
 * compiler works.)
 *
 * The IP header size, in bytes, is the value of the IP header length,
 * as extracted from the "ip_vhl" field of "struct sniff_ip" with
 * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
 * 4-byte words).  If that value is less than 20 - i.e., if the value
 * extracted with "IP_HL()" is less than 5 - you have a malformed
 * IP datagram.
 *
 * The TCP header size, in bytes, is the value of the TCP data offset,
 * as extracted from the "th_offx2" field of "struct sniff_tcp" with
 * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
 * If that value is less than 20 - i.e., if the value extracted with
 * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
 *
 * So, to find the IP header in an Ethernet packet, look 14 bytes after
 * the beginning of the packet data.  To find the TCP header, look
 * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
 * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
 * header.
 *
 * To find out how much payload there is:
 *
 * Take the IP *total* length field - "ip_len" in "struct sniff_ip"
 * - and, first, check whether it's less than "IP_HL(ip)*4" (after
 * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
 * a malformed IP datagram.
 *
 * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
 * of the TCP segment, including the TCP header.  If that's less than
 * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
 * you have a malformed TCP segment.
 *
 * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
 * length of the TCP payload.
 *
 * Note that you also need to make sure that you don't go past the end
 * of the captured data in the packet - you might, for example, have a
 * 15-byte Ethernet packet that claims to contain an IP datagram, but if
 * it's 15 bytes, it has only one byte of Ethernet payload, which is too
 * small for an IP header.  The length of the captured data is given in
 * the "caplen" field in the "struct pcap_pkthdr"; it might be less than
 * the length of the packet, if you're capturing with a snapshot length
 * other than a value >= the maximum packet size.
 * <end of response>
 *
 ****************************************************************************
 *
 * Example compiler command-line for GCC:
 *   gcc -Wall -o sniffex sniffex.c -lpcap
 *
 ****************************************************************************
 *
 * Code Comments
 *
 * This section contains additional information and explanations regarding
 * comments in the source code. It serves as documentaion and rationale
 * for why the code is written as it is without hindering readability, as it
 * might if it were placed along with the actual code inline. References in
 * the code appear as footnote notation (e.g. [1]).
 *
 * 1. Ethernet headers are always exactly 14 bytes, so we define this
 * explicitly with "#define". Since some compilers might pad structures to a
 * multiple of 4 bytes - some versions of GCC for ARM may do this -
 * "sizeof (struct sniff_ethernet)" isn't used.
 *
 * 2. Check the link-layer type of the device that's being opened to make
 * sure it's Ethernet, since that's all we handle in this example. Other
 * link-layer types may have different length headers (see [1]).
 *
 * 3. This is the filter expression that tells libpcap which packets we're
 * interested in (i.e. which packets to capture). Since this source example
 * focuses on IP and TCP, we use the expression "ip", so we know we'll only
 * encounter IP packets. The capture filter syntax, along with some
 * examples, is documented in the tcpdump man page under "expression."
 * Below are a few simple examples:
 *
 * Expression			Description
 * ----------			-----------
 * ip					Capture all IP packets.
 * tcp					Capture only TCP packets.
 * tcp port 80			Capture only TCP packets with a port equal to 80.
 * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
 *
 ****************************************************************************
 *
 */

#define APP_NAME		"Sensor"
#define APP_DESC		"Sniffer using libpcap"
#define APP_COPYRIGHT	"(c) 2013 Equilibrium Networks, Incorporated"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <pthread.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/*
 * app name/banner
 */
void print_app_banner(void) {
	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");
}

/*
 * print help text
 */
void print_app_usage(void) {
	printf("Usage: %s [options]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("	--dev	Listen on <dev> for packets.\n");
	printf("\n");
}

/*
 * process packet
 */
void Process(const struct pcap_pkthdr *, const u_char *);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* define ethernet header */
	//const struct ether_header *hdr_ethernet = (struct ether_header*)(packet);

	/* define/compute ip header offset */
	const struct ip *hdr_ip = (struct ip*)(packet + SIZE_ETHERNET);
	int size_ip = hdr_ip->ip_hl*4;
	if (size_ip < 20) {
		printf("* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* determine protocol */
	u_char ip_p = hdr_ip->ip_p;
	if (ip_p == IPPROTO_TCP) {
			/* define/compute tcp header offset */
			const struct tcphdr *hdr_tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
			int size_tcp = hdr_tcp->doff*4;
			if (size_tcp < 20) {
				printf("* Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
	} else if (ip_p == IPPROTO_UDP) {
			/* define/compute udp header offset */
			const struct udphdr *hdr_udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
			if (hdr_udp->len < 8) {
				printf("* Invalid UDP length: %u bytes\n", hdr_udp->len);
				return;
			}
	} else if (ip_p == IPPROTO_ICMP) {
			/* define/compute icmp header offset */
			//const struct icmp *hdr_icmp = (struct icmp*)(packet + SIZE_ETHERNET + size_ip);
			// Validate hdr_icmp->icmp_code?
	} else {
			printf("* Unhandled protocol: %u\n", hdr_ip->ip_p);
			return;
	}

	Process(header, packet);
}

char *dev = NULL;			/* capture device name */
char *filter_exp = "ip";		/* filter expression [3] */
void SensorInit(int, char **);
int fd_analyzer = -1; // the Analyzer's file descriptor
int fd_sdb = -1; // the SDB's file descriptor
int main(int argc, char **argv) {
	SensorInit(argc, argv);

	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

	print_app_banner();

	/* find a capture device if not specified on command-line */
	if (dev == NULL) {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	pcap_t *handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet device\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	struct bpf_program fp;			/* compiled filter program (expression) */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	printf("Capturing packets on device %s...\n", dev);
	pcap_loop(handle, 0, got_packet, NULL);

	/* cleanup
	pcap_freecode(&fp);
	pcap_close(handle);
	if (fd_analyzer != -1) close(fd_analyzer);
	if (fd_sdb != -1) close(fd_sdb);
	printf("\nCapture complete.\n");

	return 0;*/
}

// Equilibrium Networks, Inc.:
#include "tables.h"
#include "tree.h"
#include "treeFunctions.h"

#pragma pack(push,1)
struct packet_analyzer {
	u_int64_t ts; // (NTP format)
	u_int8_t cnt;
	u_int8_t src;
	u_int8_t dst;
};
#pragma pack(pop)

#pragma pack(push,1)
struct packet_sdb {
	struct packet_analyzer analyzer;
	struct ip iph;
	union {
		struct tcphdr tcph;
		struct udphdr udph;
		struct icmp icmph;
	} next_hdr;
	u_int8_t *data;
};
#pragma pack(pop)

char *name = "default.tree"; // the name of the tree file
int n_leaves = 0; // the number of leaves in the tree
int port_analyzer = -1; // the listening port for the Analyzer
int port_sdb = -1; // the listening port for the SDB
unsigned int len_ip = 1; // the length of the IP history
unsigned int len_port = 1; // the length of the port history
unsigned int len_pair = 1; // the length of the (socket) pair history
unsigned int len_sample = 1; // the length of the sample history
unsigned int skip = 0; // the number of packets to skip between samples
node* root; // the root of the classification tree
u_int64_t ts_prev = 0; // the previous timestamp
u_int8_t cnt = 255; // the count of timestamps equal to ts_prev
unsigned int skipped = 0; // the number of packets skipped since the previous sample
unsigned int** sums; // the number of times a (src, dst) occurred in the previous len_sample packets
u_int8_t* srcs; // the previous len_sample sources (cyclic)
u_int8_t* dsts; // the previous len_sample destinations (cyclic)
int indx = 0; // the index into srcs and dsts
short /* (boolean) */ full = 0 /* (false) */; // whether srcs and dsts are full
u_int8_t verbose = 0;

// Parses an IP Address Set.
struct IPItem *IpAddrSetParse(char *val) {
	char temp[strlen(val)];
	strcpy(temp, val);
	char *addr = strtok(temp, "[,]");
	struct IPItem *list = malloc(sizeof(struct IPItem));
	struct IPItem *item = list;
	while (addr != NULL) {
		char *dot1 = strstr(addr, ".");
		char *dot2 = strstr(dot1 + 1, ".");
		char *dot3 = strstr(dot2 + 1, ".");
		char *slash = strstr(dot3 + 1, "/");
		char a[dot1 - addr + 1];
		strncpy(a, addr, dot1 - addr);
		a[dot1 - addr] = '\0';
		char b[dot2 - dot1];
		strncpy(b, dot1 + 1, dot2 - dot1 - 1);
		b[dot2 - dot1 - 1] = '\0';
		char c[dot3 - dot2];
		strncpy(c, dot2 + 1, dot3 - dot2 - 1);
		c[dot3 - dot2 - 1] = '\0';
		char d[(slash == NULL ? addr + strlen(addr) : slash) - dot3];
		strncpy(d, dot3 + 1, (slash == NULL ? addr + strlen(addr) : slash) - dot3 - 1);
		d[(slash == NULL ? addr + strlen(addr) : slash) - dot3 - 1] = '\0';
		char e[slash == NULL ? 0 : addr + strlen(addr) - slash];
		if (slash != NULL) {
			strncpy(e, slash + 1, addr + strlen(addr) - slash + 1);
			e[addr + strlen(addr) - slash - 1] = '\0';
		}
		int i;
		if (!strcmp("*", a)) for (i = 0; i < 32; i++) item->a[i] = 0xff;
		else item->a[atoi(a)/8] = 1 << (atoi(a)%8);
		if (!strcmp("*", b)) for (i = 0; i < 32; i++) item->b[i] = 0xff;
		else item->b[atoi(b)/8] = 1 << (atoi(b)%8);
		if (!strcmp("*", c)) for (i = 0; i < 32; i++) item->c[i] = 0xff;
		else item->c[atoi(c)/8] = 1 << (atoi(c)%8);
		if (!strcmp("*", d)) for (i = 0; i < 32; i++) item->d[i] = 0xff;
		else item->d[atoi(d)/8] = 1 << (atoi(d)%8);
		if (slash != NULL) {
			int size = atoi(e);
			if (size <= 8) {
				int x = (atoi(a) >> (8 - size)) << (8 - size);
				for (i = x; i < x + (1 << (8 - size)); i++) item->a[i/8] |= 1 << (i%8);
				for (i = 0; i < 32; i++) item->b[i] = 0xff;
				for (i = 0; i < 32; i++) item->c[i] = 0xff;
				for (i = 0; i < 32; i++) item->d[i] = 0xff;
			} else if (size <= 16) {
				int x = (atoi(b) >> (16 - size)) << (16 - size);
				for (i = x; i < x + (1 << (16 - size)); i++) item->b[i/8] |= 1 << (i%8);
				for (i = 0; i < 32; i++) item->c[i] = 0xff;
				for (i = 0; i < 32; i++) item->d[i] = 0xff;
			} else if (size <= 24) {
				int x = (atoi(c) >> (24 - size)) << (24 - size);
				for (i = x; i < x + (1 << (24 - size)); i++) item->c[i/8] |= 1 << (i%8);
				for (i = 0; i < 32; i++) item->d[i] = 0xff;
			} else if (size < 32) {
				int x = (atoi(d) >> (32 - size)) << (32 - size);
				for (i = x; i < x + (1 << (32 - size)); i++) item->d[i/8] |= 1 << (i%8);
			}
		}
		item->next = malloc(sizeof(struct IPItem));
		item = item->next;
		addr = strtok(NULL, "[,]");
	}
	return list;
}

// Parses port and assigns PortList.
void parsePort(char* port, char* PortList) {
	memset(PortList, 0, sizeof(char)*8192);
	char temp[strlen(port)];
	strcpy(temp, port);
	char* token = strtok(temp, "[,]"); // the next "[,]"-delimited token in port
	while (token) {
		char* p = strchr(token, ':'); // the position of ':' in token
		if (p) {
			unsigned int length = p - token; // the length of the first ':'-delimited part of token
			char port1[length]; // the first port in token
			strncpy(port1, token, length);
			char port2[strlen(token) - length - 1]; // the second port in token
			strncpy(port2, p + 1, strlen(token) - length - 1);
			unsigned short start = atoi(port1); // the start of a port range
			unsigned short finish = atoi(port2); // the finish of a port range
			if (finish < start) {
				unsigned short temp = start;
				start = finish;
				finish = temp;
			}
			unsigned short i;
			for (i = start; i <= finish; i++) PortList[i/8] |= 1<<(i%8);
		} else {
			unsigned short i = atoi(token); // the port index
			PortList[i/8] |= 1<<(i%8);
		}
		token = strtok(NULL, "[,]");
	}
}

// Parses the commond-line arguments.
void ParseArgs(int argc, char** argv) {
	int i = 1;
	while (i < argc - 1) {
		char* arg = argv[i++]; // the next argument
		char* val = argv[i++]; // the next value
		if (!strcasecmp(arg, "--dev")) dev = strcpy(malloc((strlen(val) + 1)*sizeof(char)), val);
		else if (!strcasecmp(arg, "--filter_exp")) filter_exp = strcpy(malloc((strlen(val) + 1)*sizeof(char)), val);
		else if (!strcasecmp(arg, "--tree_file")) name = strcpy(malloc((strlen(val) + 1)*sizeof(char)), val);
		else if (!strcasecmp(arg, "--verbose")) verbose = atoi(val);
		else if (!strcasecmp(arg, "--analyzer_port")) port_analyzer = atoi(val);
		else if (!strcasecmp(arg, "--sdb_port")) port_sdb = atoi(val);
		else if (!strcasecmp(arg, "--ip1")) IPList1 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--ip2")) IPList2 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--ip3")) IPList3 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--ip4")) IPList4 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--ip5")) IPList5 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--ip6")) IPList6 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--ip7")) IPList7 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--ip8")) IPList8 = IpAddrSetParse(val);
		else if (!strcasecmp(arg, "--port1")) parsePort(val, PortList1);
		else if (!strcasecmp(arg, "--port2")) parsePort(val, PortList2);
		else if (!strcasecmp(arg, "--port3")) parsePort(val, PortList3);
		else if (!strcasecmp(arg, "--port4")) parsePort(val, PortList4);
		else if (!strcasecmp(arg, "--port5")) parsePort(val, PortList5);
		else if (!strcasecmp(arg, "--port6")) parsePort(val, PortList6);
		else if (!strcasecmp(arg, "--port7")) parsePort(val, PortList7);
		else if (!strcasecmp(arg, "--port8")) parsePort(val, PortList8);
		else if (!strcasecmp(arg, "--ip_history_length")) len_ip = atoi(val);
		else if (!strcasecmp(arg, "--port_history_length")) len_port = atoi(val);
		else if (!strcasecmp(arg, "--pair_history_length")) len_pair = atoi(val);
		else if (!strcasecmp(arg, "--src_ip_frequent_threshold")) frequent_ip_src = atoi(val);
		else if (!strcasecmp(arg, "--src_ip_occasional_threshold")) occasional_ip_src = atoi(val);
		else if (!strcasecmp(arg, "--dst_ip_frequent_threshold")) frequent_ip_dst = atoi(val);
		else if (!strcasecmp(arg, "--dst_ip_occasional_threshold")) occasional_ip_dst = atoi(val);
		else if (!strcasecmp(arg, "--sp_frequent_threshold")) frequent_sp = atoi(val);
		else if (!strcasecmp(arg, "--sp_occasional_threshold")) occasional_sp = atoi(val);
		else if (!strcasecmp(arg, "--dp_frequent_threshold")) frequent_dp = atoi(val);
		else if (!strcasecmp(arg, "--dp_occasional_threshold")) occasional_dp = atoi(val);
		else if (!strcasecmp(arg, "--sample_history_length")) len_sample = atoi(val);
		else if (!strcasecmp(arg, "--skip")) skip = atoi(val);
		else {
			fprintf(stderr, "Unrecognized command-line option: %s\n", arg);
			exit(EXIT_FAILURE);
		}
	}
}

// Connects to Analyzer.
int ConnectToAnalyzer() {
	struct sockaddr_in addr_server; // the server's (Sensor's) address
	bzero((char*)&addr_server, sizeof(struct sockaddr_in));
	addr_server.sin_family = AF_INET;
	addr_server.sin_addr.s_addr = INADDR_ANY;
	addr_server.sin_port = htons(port_analyzer);
	int server = socket(AF_INET, SOCK_STREAM, 0); // the server socket
	if (server < 0) {
		printf("The Analyzer socket couldn't be created!\n");
		return 1;
	}
	if (bind(server, (struct sockaddr*)&addr_server, sizeof(struct sockaddr_in)) < 0) {
		printf("The Analyzer socket couldn't be bound!\n");
		return 2;
	}
	while (1 /* (true) */) {
		if (fd_analyzer == -1) {
			listen(server, 5);
			struct sockaddr_in addr_client; // the client's (Analyzer's) address
			unsigned int length = sizeof(struct sockaddr_in); // the length of addr_client
			int client = accept(server, (struct sockaddr*)&addr_client, &length); // the client socket
			if (client < 0) {
				printf("The Analyzer couldn't be accepted!\n");
				continue;
			}
			if (send(client, &n_leaves, sizeof(u_int8_t), 0) < 0) {
				printf("The number of leaves couldn't be sent to the SDB!\n");
				close(client);
				continue;
			}
			fd_analyzer = client;
		}
		sleep(1);
	}
	return 0;
}

// Connects to SDB.
int ConnectToSDB() {
	struct sockaddr_in addr_server; // the server's (Sensor's) address
	bzero((char*)&addr_server, sizeof(struct sockaddr_in));
	addr_server.sin_family = AF_INET;
	addr_server.sin_addr.s_addr = INADDR_ANY;
	addr_server.sin_port = htons(port_sdb);
	int server = socket(AF_INET, SOCK_STREAM, 0); // the server socket
	if (server < 0) {
		printf("The SDB socket couldn't be created!\n");
		return 1;
	}
	if (bind(server, (struct sockaddr*)&addr_server, sizeof(struct sockaddr_in)) < 0) {
		printf("The SDB socket couldn't be bound!\n");
		return 2;
	}
	while (1 /* (true) */) {
		if (fd_sdb == -1) {
			listen(server, 5);
			struct sockaddr_in addr_client; // the client's (SDB's) address
			unsigned int length = sizeof(struct sockaddr_in); // the length of addr_client
			int client = accept(server, (struct sockaddr*)&addr_client, &length); // the client socket
			if (client < 0) {
				printf("The SDB couldn't be accepted!\n");
				continue;
			}
			int8_t size = sizeof(struct packet_sdb); // the number of bytes to send
			if (send(client, &size, sizeof(int8_t), 0) < 0) {
				printf("The packet size couldn't be sent to the SDB!\n");
				close(client);
				continue;
			}
			fd_sdb = client;
		}
		sleep(1);
	}
	return 0;
}

// Initializes sensor using args.
void SensorInit(int argc, char** argv) {
	memset(PortList1, 0, sizeof(char)*8192);
	memset(PortList2, 0, sizeof(char)*8192);
	memset(PortList3, 0, sizeof(char)*8192);
	memset(PortList4, 0, sizeof(char)*8192);
	memset(PortList5, 0, sizeof(char)*8192);
	memset(PortList6, 0, sizeof(char)*8192);
	memset(PortList7, 0, sizeof(char)*8192);
	memset(PortList8, 0, sizeof(char)*8192);
	frequent_ip_src = 1;
	occasional_ip_src = 1;
	frequent_ip_dst = 1;
	occasional_ip_dst = 1;
	frequent_sp = 1;
	occasional_sp = 1;
	frequent_dp = 1;
	occasional_dp = 1;
	ParseArgs(argc, argv);
	printf("\n");
	treeCollection* forest = loadFile(name, &n_leaves);
	if (!forest) {
		printf("Sensor can't run because %s does not exist or does not contain a tree!\n", name);
		exit(EXIT_FAILURE);
	}
	root = forest->elements[0]->root;
	sums = malloc(n_leaves*sizeof(unsigned int*));
	unsigned int i;
	unsigned int j;
	for (i = 0; i < n_leaves; i++) {
		sums[i] = malloc(n_leaves*sizeof(unsigned int));
		for (j = 0; j < n_leaves; j++) sums[i][j] = 0;
	}
	srcs = malloc(len_sample*sizeof(u_int8_t));
	dsts = malloc(len_sample*sizeof(u_int8_t));
	initTables(len_port, len_port, len_ip, len_ip, len_pair);
	if (port_analyzer != -1) {
		pthread_t listener_analyzer;
		pthread_create(&listener_analyzer, NULL, (void*)ConnectToAnalyzer, NULL);
	}
	if (port_sdb != -1) {
		pthread_t listener_sdb;
		pthread_create(&listener_sdb, NULL, (void*)ConnectToSDB, NULL);
	}
}

// Process a packet (header).
void Process(const struct pcap_pkthdr *h, const u_char *p) {
	struct packet_analyzer analyzer; // an analyzer packet

	// Assign analyzer's fields.
	u_int64_t ts_curr = ((u_int64_t)h->ts.tv_sec << 32) | (u_int32_t)(h->ts.tv_usec*4294.967296); // the current timestamp
	if (ts_curr > ts_prev) {
		if (cnt) cnt = 0;
		ts_prev = ts_curr;
	} else if (ts_curr == ts_prev) cnt++;
	else {
		printf("An old packet was skipped!\n");
		return;
	}
	u_int8_t src = processTree(root, p, 1 /* (true) */); // the packet's source
	u_int8_t dst = processTree(root, p, 0 /* (false) */); // the packet's destination
	const u_char *ip_off = p + SIZE_ETHERNET;
	struct ip *hdr_ip = (struct ip*)ip_off;
	u_char ip_p = hdr_ip->ip_p;
	u_int16_t sp;
	u_int16_t dp;
	if (ip_p == IPPROTO_TCP) {
		struct tcphdr *hdr_tcp = (struct tcphdr*)(ip_off + hdr_ip->ip_hl*4);
		sp = hdr_tcp->source;
		dp = hdr_tcp->dest;
	} else if (ip_p == IPPROTO_UDP) {
		struct udphdr *hdr_udp = (struct udphdr*)(ip_off + hdr_ip->ip_hl*4);
		sp = hdr_udp->source;
		dp = hdr_udp->dest;
	}
	updateTables(hdr_ip->ip_src, hdr_ip->ip_dst, ip_p == IPPROTO_ICMP, htons(sp), htons(dp));
	analyzer.ts = ts_curr;
	analyzer.cnt = cnt;
	analyzer.src = src;
	analyzer.dst = dst;

	// Send analyzer to the Analyzer.
	if (fd_analyzer != -1 && send(fd_analyzer, &analyzer, sizeof(struct packet_analyzer), 0) < sizeof(struct packet_analyzer)) {
		close(fd_analyzer);
		fd_analyzer = -1;
		printf("A packet couldn't be sent to the Analyzer!\n");
	}

	// Conditionally send analyzer+ to the SDB.
	if (fd_sdb != -1) {
		if (full) sums[srcs[indx]][dsts[indx]]--;
		srcs[indx] = src;
		dsts[indx] = dst;
		sums[srcs[indx]][dsts[indx]]++;
		skipped++;
		if (skipped > skip || sums[srcs[indx]][dsts[indx]] == 1) {
			struct packet_sdb sdb;
			// Assign sdb's fields.
			sdb.analyzer = analyzer;
			sdb.iph = *hdr_ip;
			if (ip_p == IPPROTO_TCP) sdb.next_hdr.tcph = *(struct tcphdr*)(ip_off + hdr_ip->ip_hl*4);
			else if (ip_p == IPPROTO_UDP) sdb.next_hdr.udph = *(struct udphdr*)(ip_off + hdr_ip->ip_hl*4);
			else sdb.next_hdr.icmph = *((struct icmp*)(ip_off + hdr_ip->ip_hl*4));
			sdb.data = (u_int8_t *)(ip_off + hdr_ip->ip_len);
			// Send sdb to the SDB.
			if (send(fd_sdb, &sdb, sizeof(struct packet_sdb), 0) < sizeof(struct packet_sdb)) {
				close(fd_sdb);
				fd_sdb = -1;
				printf("A packet couldn't be sent to the SDB!\n");
			}

			// Reset the simple sampler.
			if (skipped > skip) skipped = 0;
		}
		indx++;
		if (indx == len_sample) {
			indx = 0;
			full = 1 /* (true) */;
		}
	}
	// for testing
	if (verbose) {
		char *addr = (char *)inet_ntoa(hdr_ip->ip_src);
		char *addr_src = strcpy(malloc((strlen(addr) + 1)*sizeof(char)), addr);
		printf("%s %s:%i %s:%i -> %llu %i %i %i\n", ip_p == IPPROTO_TCP ? "TCP" : ip_p == IPPROTO_UDP ? "UDP" : "ICMP", addr_src, ip_p == IPPROTO_ICMP ? -1 : ntohs(sp), inet_ntoa(hdr_ip->ip_dst), ip_p == IPPROTO_ICMP ? -1 : ntohs(dp), ts_curr, cnt, src, dst);
	}
}
