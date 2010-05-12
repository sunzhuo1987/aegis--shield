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
 
#ifndef _FLOW_CACHE_H
#define _FLOW_CACHE_H

#include "flow.h"
#include "sfxhash.h"
#include "sf_types.h"


typedef struct _FCSTAT
{
    UINT64 find_ops;
    UINT64 reversed_ops;
    UINT64 find_success;
    UINT64 find_fail;
    UINT64 new_flows;
    UINT64 released_flows;
} FCSTAT;

typedef struct _FLOWCACHE
{
    SFXHASH *ipv4_table;
    /* statistics */
    FCSTAT total;            /* statistics for everything */
    FCSTAT per_proto[256];   /* statistics kept per protocol */
    unsigned int max_flowbits_bytes;
} FLOWCACHE;


int flowcache_init(FLOWCACHE *flowcachep, unsigned int rows, int memcap,
                   int datasize, FLOWHASHID hashid);
int flowcache_destroy(FLOWCACHE *flowcachep);
int flowcache_releaseflow(FLOWCACHE *flowcachep, FLOW **flowpp);
int flowcache_newflow(FLOWCACHE *flowcachep, FLOWKEY *keyp, FLOW **flowpp);
int flowcache_find(FLOWCACHE *flowcachep, FLOWKEY *keyp,
                   FLOW **flowpp, int *direction);

void flowcache_stats(FILE *stream, FLOWCACHE *flowcachep);

int flowcache_overhead_bytes(FLOWCACHE *fcp);

int flowcache_memcap(FLOWCACHE *fcp);
int flowcache_row_count(FLOWCACHE *fcp);

/* utilty functions */
const char *flowcache_pname(FLOW_POSITION position);

#endif /* _FLOW_CACHE_H */
