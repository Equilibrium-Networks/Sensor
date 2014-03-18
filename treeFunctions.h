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

/* treeFunctions.h
 *   @author cc, gt
 *   Version 0.9
 */

// Load once and C++ safety definitions.
#ifndef _TREEFUNCTIONS_H_
#define _TREEFUNCTIONS_H_

#ifdef __cplusplus
extern "C" {
#endif

// Include files.
#include <stdlib.h>

// The IP lists (8 parts (bits) per char (byte)):
struct IPItem {
    char a[32];
    char b[32];
    char c[32];
    char d[32];
    struct IPItem *next;
};
extern struct IPItem *IPList1;
extern struct IPItem *IPList2;
extern struct IPItem *IPList3;
extern struct IPItem *IPList4;
extern struct IPItem *IPList5;
extern struct IPItem *IPList6;
extern struct IPItem *IPList7;
extern struct IPItem *IPList8;

// The port lists (8 ports (bits) per char (byte)):
extern char PortList1[8192];
extern char PortList2[8192];
extern char PortList3[8192];
extern char PortList4[8192];
extern char PortList5[8192];
extern char PortList6[8192];
extern char PortList7[8192];
extern char PortList8[8192];

// Function pointer type definition.
typedef int /* (boolean) */ (*funcPointer)(const u_char *, int /* (boolean) */);

// Function prototypes.
funcPointer findFunction(char *name);
int /* (boolean) */ isTCP(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isUDP(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isICMP(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList1(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList2(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList3(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList4(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList5(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList6(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList7(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInIPList8(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList1(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList2(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList3(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList4(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList5(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList6(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList7(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isInPortList8(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isFrequentIP(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isOccasionalIP(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isFrequentPort(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isOccasionalPort(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isAttached(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isICMPRequest(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isICMPReply(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isICMPError(const u_char *p, int /* (boolean) */ source);
int /* (boolean) */ isICMPOther(const u_char *p, int /* (boolean) */ source);

#ifdef __cplusplus
}
#endif

#endif /* _TREEFUNCTIONS_H_ */
