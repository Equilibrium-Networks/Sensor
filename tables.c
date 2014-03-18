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

/* tables.c
 *   @author gt
 *   Version 0.9
 */

// Include files.
#include <stdlib.h>
#include "tables.h"
#include "uthash.h"

unsigned int frequent_ip_src = 1;
unsigned int occasional_ip_src = 1;
unsigned int frequent_ip_dst = 1;
unsigned int occasional_ip_dst = 1;
unsigned int frequent_sp = 1;
unsigned int occasional_sp = 1;
unsigned int frequent_dp = 1;
unsigned int occasional_dp = 1;

unsigned int len_sp;
unsigned int len_dp;
unsigned int len_ip_src;
unsigned int len_ip_dst;
unsigned int len_pair;

struct addr { // an IP address
	struct in_addr ip;
	unsigned int frequency; // the frequency of this
	UT_hash_handle hh;
};

struct key_pair { // a socket pair key
	struct in_addr ip_src;
	u_int16_t sp;
	struct in_addr ip_dst;
	u_int16_t dp;
};

struct pair { // a socket pair
	struct key_pair key;
	unsigned int frequency; // the frequency of this
	UT_hash_handle hh;
};

struct addr* head_ip_src = NULL; // the head of the source IP address hash
struct addr** pool_ip_src = NULL; // the pool of source IP address structs (FILO)
unsigned int next_ip_src = 0; // the index of the next source IP address struct in pool_ip_src
struct addr** history_ip_src = NULL; // the previous len_ip_src source IP addresses (cyclic)
unsigned int oldest_ip_src = 0; // the index of the oldest source IP address in history_ip_src
struct addr* head_ip_dst = NULL; // the head of the destination IP address hash
struct addr** pool_ip_dst = NULL; // the pool of destination IP address structs (FILO)
unsigned int next_ip_dst = 0; // the next destination IP address struct in pool_ip_dst
struct addr** history_ip_dst = NULL; // the previous len_ip_dst destination IP addresses (cyclic)
unsigned int oldest_ip_dst = 0; // the index of the oldest destination IP address in history_ip_dst
unsigned int frequencies_sp[65536]; // the frequency of each source port
u_int16_t* history_sp = NULL; // the previous len_sp source ports (cyclic)
u_int16_t oldest_sp = 0; // the index of the oldest source port in history_sp
int /* (boolean) */ complete_sp = 0 /* (false) */; // whether the initialization of history_sp is complete
unsigned int frequencies_dp[65536]; // the frequency of each destination port
u_int16_t* history_dp = NULL; // the previous len_dp destination ports (cyclic)
u_int16_t oldest_dp = 0; // the index of the oldest destination port in history_dp
int /* (boolean) */ complete_dp = 0 /* (false) */; // whether the initialization of history_dp is complete
struct pair* head_pair = NULL; // the head of the socket pair hash
struct pair** pool_pair = NULL; // the pool of socket pair structs (FILO)
unsigned int next_pair = 0; // the next socket pair struct in pool_pair
struct pair** history_pair = NULL; // the previous len_pair socket pairs (cyclic)
unsigned int oldest_pair = 0; // the index of the oldest socket pair in history_pair
struct key_pair key;

// Initialize the tables and the key_pair struct.
void initTables(unsigned int _len_sp, unsigned int _len_dp, unsigned int _len_ip_src, unsigned int _len_ip_dst, unsigned int _len_pair) {
	len_sp = _len_sp;
	len_dp = _len_dp;
	len_ip_src = _len_ip_src;
	len_ip_dst = _len_ip_dst;
	len_pair = _len_pair;

	unsigned int i; // a loop control variable

	// Initialize pool_ip_src.
	pool_ip_src = malloc(len_ip_src*sizeof(struct addr*));
	for (i = 0; i < len_ip_src; i++) {
		pool_ip_src[i] = malloc(sizeof(struct addr));
		pool_ip_src[i]->frequency = 1; // so the field does not have to be incremented before the struct is added to a hash
	}

	// Initialize history_ip_src.
	history_ip_src = malloc(len_ip_src*sizeof(struct addr*));
	for (i = 0; i < len_ip_src; i++) history_ip_src[i] = NULL;

	// Initialize pool_ip_dst.
	pool_ip_dst = malloc(len_ip_dst*sizeof(struct addr*));
	for (i = 0; i < len_ip_dst; i++) {
		pool_ip_dst[i] = malloc(sizeof(struct addr));
		pool_ip_dst[i]->frequency = 1; // so the field does not have to be incremented before the struct is added to a hash
	}

	// Initialize history_ip_dst.
	history_ip_dst = malloc(len_ip_dst*sizeof(struct addr*));
	for (i = 0; i < len_ip_dst; i++) history_ip_dst[i] = NULL;

	// Initialize frequencies_sp.
	for (i = 0; i < 65536; i++) frequencies_sp[i] = 0;

	// Initialize history_sp.
	history_sp = malloc(len_sp*sizeof(u_int16_t));

	// Initialize frequencies_dp.
	for (i = 0; i < 65536; i++) frequencies_dp[i] = 0;

	// Initialize history_dp.
	history_dp = malloc(len_dp*sizeof(u_int16_t));

	// Initialize pool_pair.
	pool_pair = malloc(len_pair*sizeof(struct pair*));
	for (i = 0; i < len_pair; i++) {
		pool_pair[i] = malloc(sizeof(struct pair));
		memset(&pool_pair[i]->key, 0, sizeof(struct key_pair)); // to zero out any padding between the key fields
		pool_pair[i]->frequency = 1; // so the field does not have to be incremented before the struct is added to a hash
	}

	// Initialize history_pair.
	history_pair = malloc(len_pair*sizeof(struct pair*));
	for (i = 0; i < len_pair; i++) history_pair[i] = NULL;

	// Initialize key.
	memset(&key, 0, sizeof(struct key_pair));
}

// Update the tables.
void updateTables(struct in_addr ip_src, struct in_addr ip_dst, int /* (boolean) */ icmp, u_int16_t sp, u_int16_t dp) {
	// Update the source-IP-address table.
	struct addr* old_ip_src = history_ip_src[oldest_ip_src];
	if (old_ip_src) {
		if (1 == old_ip_src->frequency) {
			HASH_DELETE(hh, head_ip_src, old_ip_src);
			next_ip_src--;
			pool_ip_src[next_ip_src] = old_ip_src;
		} else old_ip_src->frequency--;
	}
	struct addr* new_ip_src;
	HASH_FIND(hh, head_ip_src, &ip_src, sizeof(struct in_addr), new_ip_src);
	if (!new_ip_src) {
		new_ip_src = pool_ip_src[next_ip_src];
		next_ip_src++;
		new_ip_src->ip = ip_src;
		HASH_ADD(hh, head_ip_src, ip, sizeof(struct in_addr), new_ip_src);
	} else new_ip_src->frequency++;
	history_ip_src[oldest_ip_src] = new_ip_src;
	oldest_ip_src = (oldest_ip_src + 1)%len_ip_src;

	// Update the destination-IP-address table.
	struct addr* old_ip_dst = history_ip_dst[oldest_ip_dst];
	if (old_ip_dst) {
		if (1 == old_ip_dst->frequency) {
			HASH_DELETE(hh, head_ip_dst, old_ip_dst);
			next_ip_dst--;
			pool_ip_dst[next_ip_dst] = old_ip_dst;
		} else old_ip_dst->frequency--;
	}
	struct addr* new_ip_dst;
	HASH_FIND(hh, head_ip_dst, &ip_dst, sizeof(struct in_addr), new_ip_dst);
	if (!new_ip_dst) {
		new_ip_dst = pool_ip_dst[next_ip_dst];
		next_ip_dst++;
		new_ip_dst->ip = ip_dst;
		HASH_ADD(hh, head_ip_dst, ip, sizeof(struct in_addr), new_ip_dst);
	} else new_ip_dst->frequency++;
	history_ip_dst[oldest_ip_dst] = new_ip_dst;
	oldest_ip_dst = (oldest_ip_dst + 1)%len_ip_dst;

	// Conditionally update the source-port, destination-port, and socket-pair tables.
	if (!icmp) {
		// Update the source-port table.
		if (complete_sp) frequencies_sp[history_sp[oldest_sp]]--;
		else if (len_sp - 1 == oldest_sp) complete_sp = 1 /* (true) */;
		frequencies_sp[sp]++;
		history_sp[oldest_sp] = sp;
		oldest_sp = (oldest_sp + 1)%len_sp;

		// Update the destination-port table.
		if (complete_dp) frequencies_dp[history_dp[oldest_dp]]--;
		else if (len_dp - 1 == oldest_dp) complete_dp = 1 /* (true) */;
		frequencies_dp[dp]++;
		history_dp[oldest_dp] = dp;
		oldest_dp = (oldest_dp + 1)%len_dp;

		// Update the socket-pair table.
		struct pair* old_pair = history_pair[oldest_pair];
		if (old_pair) {
			if (1 == old_pair->frequency) {
				HASH_DELETE(hh, head_pair, old_pair);
				next_pair--;
				pool_pair[next_pair] = old_pair;
			} else old_pair->frequency--;
		}
		key.ip_src = ip_src;
		key.sp = sp;
		key.ip_dst = ip_dst;
		key.dp = dp;
		struct pair* new_pair;
		HASH_FIND(hh, head_pair, &key, sizeof(struct key_pair), new_pair);
		if (!new_pair) {
			new_pair = pool_pair[next_pair];
			next_pair++;
			struct key_pair* key_new_pair = &new_pair->key;
			key_new_pair->ip_src = ip_src;
			key_new_pair->sp = sp;
			key_new_pair->ip_dst = ip_dst;
			key_new_pair->dp = dp;
			HASH_ADD(hh, head_pair, key, sizeof(struct key_pair), new_pair);
		} else new_pair->frequency++;
		history_pair[oldest_pair] = new_pair;
		oldest_pair = (oldest_pair + 1)%len_pair;
	}
}

// Return whether the passed source-IP address is frequent.
int /* (boolean) */ isFrequentIPSrc(struct in_addr ip_src) {
	struct addr* ip;
	HASH_FIND(hh, head_ip_src, &ip_src, sizeof(struct in_addr), ip);
	if (ip && frequent_ip_src <= ip->frequency) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed source-IP address is occasional.
int /* (boolean) */ isOccasionalIPSrc(struct in_addr ip_src) {
	struct addr* ip;
	HASH_FIND(hh, head_ip_src, &ip_src, sizeof(struct in_addr), ip);
	if (ip && occasional_ip_dst <= ip->frequency) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed destination-IP address is frequent.
int /* (boolean) */ isFrequentIPDst(struct in_addr ip_dst) {
	struct addr* ip;
	HASH_FIND(hh, head_ip_dst, &ip_dst, sizeof(struct in_addr), ip);
	if (ip && frequent_ip_dst <= ip->frequency) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed destination-IP address is occasional.
int /* (boolean) */ isOccasionalIPDst(struct in_addr ip_dst) {
	struct addr* ip;
	HASH_FIND(hh, head_ip_dst, &ip_dst, sizeof(struct in_addr), ip);
	if (ip && occasional_ip_dst <= ip->frequency) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed source port is frequent.
int /* (boolean) */ isFrequentPortSrc(u_int16_t sp) {
	if (frequent_sp <= frequencies_sp[sp]) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed source port is occasional.
int /* (boolean) */ isOccasionalPortSrc(u_int16_t sp) {
	if (occasional_sp <= frequencies_sp[sp]) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed destination port is frequent.
int /* (boolean) */ isFrequentPortDst(u_int16_t dp) {
	if (frequent_dp <= frequencies_dp[dp]) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed destination port is occasional.
int /* (boolean) */ isOccasionalPortDst(u_int16_t dp) {
	if (occasional_dp <= frequencies_dp[dp]) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed socket pair is attached.
int /* (boolean) */ isAttachedSrc(struct in_addr ip_src, u_int16_t sp, struct in_addr ip_dst, u_int16_t dp) {
	key.ip_src = ip_src;
	key.sp = sp;
	key.ip_dst = ip_dst;
	key.dp = dp;
	struct pair* pair_src;
	HASH_FIND(hh, head_pair, &key, sizeof(struct key_pair), pair_src);
	if (!pair_src) return 0 /* (false) */;
	// isAttachedDst(ip_src, sp, ip_dst, dp):
	key.ip_src = ip_dst;
	key.sp = dp;
	key.ip_dst = ip_src;
	key.dp = sp;
	struct pair* pair_dst;
	HASH_FIND(hh, head_pair, &key, sizeof(struct key_pair), pair_dst);
	if (/* pair_src && */ pair_dst) return 1 /* (true) */;
	return 0 /* (false) */;
}

// Return whether the passed socket pair is attached.
int /* (boolean) */ isAttachedDst(struct in_addr ip_src, u_int16_t sp, struct in_addr ip_dst, u_int16_t dp) {
	key.ip_src = ip_dst;
	key.sp = dp;
	key.ip_dst = ip_src;
	key.dp = sp;
	struct pair* pair_dst;
	HASH_FIND(hh, head_pair, &key, sizeof(struct key_pair), pair_dst);
	if (pair_dst) return 1 /* (true) */;
	return 0 /* (false) */;
}
