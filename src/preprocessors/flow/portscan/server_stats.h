/****************************************************************************
 *
 * Copyright (C) 2003-2008 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ****************************************************************************/
 
#ifndef _SERVER_STATS_H
#define _SERVER_STATS_H

#include <stdio.h>

#include "flowps.h"
#include "sfxhash.h"
#include "ipobj.h"

#define SERVER_STATS_MAX_HITCOUNT 0xFFFFFFFF

void server_stats(SERVER_STATS *ssp, int dumpall);
void server_stats_dump(SERVER_STATS *ssp);

int server_stats_init(SERVER_STATS *ssp, IPSET *watchnet, unsigned int rows, int memcap);
int server_stats_destroy(SERVER_STATS *ssp);

u_int32_t server_stats_hitcount_ipv4(SERVER_STATS *ssp,
                                    u_int8_t ip_proto,
                                    u_int32_t address,
                                    u_int16_t port);

int server_stats_add_ipv4(SERVER_STATS *ssp, u_int8_t ip_proto, u_int32_t address,
                          u_int16_t port, u_int32_t *retcount);

int server_stats_remove_ipv4(SERVER_STATS *ssp, u_int8_t ip_proto, u_int32_t address, u_int16_t port);

int server_stats_save(SERVER_STATS *ssp, char *filename);

int server_stats_row_count(SERVER_STATS *sbp);
int server_stats_memcap(SERVER_STATS *sbp);
int server_stats_overhead_bytes(SERVER_STATS *sbp);
int server_stats_contains(SERVER_STATS *ssp, u_int32_t address);
#endif /* _SERVER_STATS_H */
