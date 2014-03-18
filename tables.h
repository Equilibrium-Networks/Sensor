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

/* tables.h
 *   @author gt
 *   Version 0.9
 */

// Include files.
#include <netinet/in.h>

extern unsigned int frequent_ip_src;
extern unsigned int occasional_ip_src;
extern unsigned int frequent_ip_dst;
extern unsigned int occasional_ip_dst;
extern unsigned int frequent_sp;
extern unsigned int occasional_sp;
extern unsigned int frequent_dp;
extern unsigned int occasional_dp;

void initTables(unsigned int _len_sp, unsigned int _len_dp, unsigned int _len_ip_src, unsigned int _len_ip_dst, unsigned int _len_pair);
void updateTables(struct in_addr ip_src, struct in_addr ip_dst, int /* (boolean) */ icmp, u_int16_t sp, u_int16_t dp);
int /* (boolean) */ isFrequentIPSrc(struct in_addr ip_src);
int /* (boolean) */ isOccasionalIPSrc(struct in_addr ip_src);
int /* (boolean) */ isFrequentIPDst(struct in_addr ip_dst);
int /* (boolean) */ isOccasionalIPDst(struct in_addr ip_dst);
int /* (boolean) */ isFrequentPortSrc(u_int16_t sp);
int /* (boolean) */ isOccasionalPortSrc(u_int16_t sp);
int /* (boolean) */ isFrequentPortDst(u_int16_t dp);
int /* (boolean) */ isOccasionalPortDst(u_int16_t dp);
int /* (boolean) */ isAttachedSrc(struct in_addr ip_src, u_int16_t sp, struct in_addr ip_dst, u_int16_t dp);
int /* (boolean) */ isAttachedDst(struct in_addr ip_src, u_int16_t sp, struct in_addr ip_dst, u_int16_t dp);
