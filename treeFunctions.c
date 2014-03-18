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

/* treeFunctions.c
 *   @author cc, gt
 *   Version 0.9
 */

// Include files.
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include "tables.h"
#include "treeFunctions.h"

#define IP_HL(ip)               (ip)->ip_hl

// The IP address lists:
struct IPItem *IPList1;
struct IPItem *IPList2;
struct IPItem *IPList3;
struct IPItem *IPList4;
struct IPItem *IPList5;
struct IPItem *IPList6;
struct IPItem *IPList7;
struct IPItem *IPList8;

// The port lists (8 ports (bits) per char (byte)):
char PortList1[8192];
char PortList2[8192];
char PortList3[8192];
char PortList4[8192];
char PortList5[8192];
char PortList6[8192];
char PortList7[8192];
char PortList8[8192];

/*
 * Function name lookup table. This table is matched with the function pointer
 * table declared below. This table allows function lookup based on the actual
 * function name, as declared by a string. The names here should be modified,
 * added to, or removed from as appropriate to support implementation specific
 * functions. The function names used in any tree definition file must match
 * the list below in order to processed properly. The names are case sensitive.
 */
const char* funcNameTable[] =
{
    "isTCP",
    "isUDP",
    "isICMP",
    "isInIPList1",
    "isInIPList2",
    "isInIPList3",
    "isInIPList4",
    "isInIPList5",
    "isInIPList6",
    "isInIPList7",
    "isInIPList8",
    "isInPortList1",
    "isInPortList2",
    "isInPortList3",
    "isInPortList4",
    "isInPortList5",
    "isInPortList6",
    "isInPortList7",
    "isInPortList8",
    "isFrequentIP",
    "isOccasionalIP",
    "isFrequentPort",
    "isOccasionalPort",
    "isAttached",
    "isICMPRequest",
    "isICMPReply",
    "isICMPError",
    "isICMPOther"
};

/*
 * Function pointer lookup table. This table is matched with the function
 * pointer name table above. This table allows a function pointer to be
 * retrieved by index number. The index numbers for both this and the name table
 * are expected to match for all given function pointer and function name pairs.
 * The functions in this list should correspond to the internal representations
 * of each possible function available for a tree definition file.
 */
const funcPointer funcPointerTable[] =
{
    &isTCP,
    &isUDP,
    &isICMP,
    &isInIPList1,
    &isInIPList2,
    &isInIPList3,
    &isInIPList4,
    &isInIPList5,
    &isInIPList6,
    &isInIPList7,
    &isInIPList8,
    &isInPortList1,
    &isInPortList2,
    &isInPortList3,
    &isInPortList4,
    &isInPortList5,
    &isInPortList6,
    &isInPortList7,
    &isInPortList8,
    &isFrequentIP,
    &isOccasionalIP,
    &isFrequentPort,
    &isOccasionalPort,
    &isAttached,
    &isICMPRequest,
    &isICMPReply,
    &isICMPError,
    &isICMPOther
};

/*
 * Returns a function pointer matching the passed in name. The lookup table is
 * searched for the first name that matches the parameter (case sensitive), and
 * uses the matching index to return the corresponding function pointer. If a
 * name cannot be found, then a NULL pointer is returned. Name strings are
 * expected to be properly NULL terminated.
 */
funcPointer findFunction(char *name)
{
    // Find and return appropriate function by name.
    int x;
    for(x = 0; x < 28; x++)
    {
        // Check lookup table.
        if(strstr(funcNameTable[x], name) != NULL)
        {
            // Return found function pointer.
            return funcPointerTable[x];
        }
    }

    // Not found, return NULL function pointer.
    printf("Function %s does not exist!", name);
    exit(28);
}

int /* (boolean) */ isTCP(const u_char *p, int /* (boolean) */ source) {
    return ((struct ip*)(p + 14))->ip_p == IPPROTO_TCP;
}

int /* (boolean) */ isUDP(const u_char *p, int /* (boolean) */ source) {
    return ((struct ip*)(p + 14))->ip_p == IPPROTO_UDP;
}

int /* (boolean) */ isICMP(const u_char *p, int /* (boolean) */ source) {
    return ((struct ip*)(p + 14))->ip_p == IPPROTO_ICMP;
}

int /* (boolean) */ isInIPList1(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList1, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInIPList2(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList2, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInIPList3(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList3, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInIPList4(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList4, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInIPList5(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList5, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInIPList6(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList6, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInIPList7(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList7, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInIPList8(const u_char *p, int /* (boolean) */ source) {
    return IPListContains(IPList8, source ? ((struct ip*)(p + 14))->ip_src : ((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isInPortList1(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList1[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isInPortList2(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList2[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isInPortList3(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList3[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isInPortList4(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList4[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isInPortList5(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList5[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isInPortList6(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList6[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isInPortList7(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList7[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isInPortList8(const u_char *p, int /* (boolean) */ source) {
    u_int16_t port = htons(source ? (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source) : (isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
    return PortList8[port/8]&(1<<(port%8)) ? 1 /* (true) */ : 0 /* (false) */;
}

int /* (boolean) */ isFrequentIP(const u_char *p, int /* (boolean) */ source) {
    return source ? isFrequentIPSrc(((struct ip*)(p + 14))->ip_src) : isFrequentIPDst(((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isOccasionalIP(const u_char *p, int /* (boolean) */ source) {
    return source ? isOccasionalIPSrc(((struct ip*)(p + 14))->ip_src) : isOccasionalIPDst(((struct ip*)(p + 14))->ip_dst);
}

int /* (boolean) */ isFrequentPort(const u_char *p, int /* (boolean) */ source) {
    return source ? isFrequentPortSrc(htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source)) : isFrequentPortDst(htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
}

int /* (boolean) */ isOccasionalPort(const u_char *p, int /* (boolean) */ source) {
    return source ? isOccasionalPortSrc(htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source)) : isOccasionalPortDst(htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
}

int /* (boolean) */ isAttached(const u_char *p, int /* (boolean) */ source) {
    return source ? isAttachedSrc(((struct ip*)(p + 14))->ip_src, htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source), ((struct ip*)(p + 14))->ip_dst, htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest)) : isAttachedDst(((struct ip*)(p + 14))->ip_src, htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->source), ((struct ip*)(p + 14))->ip_dst, htons(isTCP(p, source) ? ((struct tcphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest : ((struct udphdr*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->dest));
}

int /* (boolean) */ isICMPRequest(const u_char *p, int /* (boolean) */ source) {
    if (source) switch (((struct icmp*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->icmp_type) {
        case 8:
        case 10:
        case 13:
        case 15:
        case 17:
            return 1 /* (true) */;
        default:
            return 0 /* (false) */;
    } else switch (((struct icmp*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->icmp_type) {
        case 0:
        case 9:
        case 14:
        case 16:
        case 18:
            return 1 /* (true) */;
        default:
            return 0 /* (false) */;
    }
}

int /* (boolean) */ isICMPReply(const u_char *p, int /* (boolean) */ source) {
    if (source) switch (((struct icmp*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->icmp_type) {
        case 0:
        case 9:
        case 14:
        case 16:
        case 18:
            return 1 /* (true) */;
        default:
            return 0 /* (false) */;
    } else switch (((struct icmp*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->icmp_type) {
        case 8:
        case 10:
        case 13:
        case 15:
        case 17:
            return 1 /* (true) */;
        default:
            return 0 /* (false) */;
    }
}

int /* (boolean) */ isICMPError(const u_char *p, int /* (boolean) */ source) {
    switch (((struct icmp*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->icmp_type) {
        case 3:
        case 4:
        case 5:
        case 11:
        case 12:
            return source;
        default:
            return !source;
    }
}

int /* (boolean) */ isICMPOther(const u_char *p, int /* (boolean) */ source) {
    switch (((struct icmp*)(p + 14 + IP_HL((struct ip*)(p + 14))*4))->icmp_type) {
        case 0:
        case 3:
        case 4:
        case 5:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
            return !source;
        default:
            return source;
    }
}

int IPListContains(const struct IPItem *list, struct in_addr in) {
    if (list == NULL) return 0;
    struct IPItem item = *list;
    while (1) {
        //printf("addr = %s\n", inet_ntoa(in));
        uint32_t s = in.s_addr;
        unsigned char a = s%256;
        unsigned char b = (s>>8)%256;
        unsigned char c = (s>>16)%256;
        unsigned char d = (s>>24)%256;
        //printf("item = %i.%i.%i.%i\n", a, b, c, d);
        if (item.a[a/8]&(1<<(a%8)) && item.b[b/8]&(1<<(b%8)) && item.c[c/8]&(1<<(c%8)) && item.d[d/8]&(1<<(d%8))) return 1;
        if (item.next == NULL) return 0;
        else item = *item.next;
    }
}
