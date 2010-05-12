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
 
#ifndef _UNIQUE_TRACKER_H
#define _UNIQUE_TRACKER_H

#include "flow.h"
#include "sfxhash.h"

typedef enum {
    UT_OLD,
    UT_NEW
} UT_TYPE;


typedef struct _UNIQUE_TRACKER
{
    SFXHASH *ipv4_table;
} UNIQUE_TRACKER;

int ut_init(UNIQUE_TRACKER *utp, unsigned int rows, int memcap);
int ut_destroy(UNIQUE_TRACKER *utp);
int ut_check(UNIQUE_TRACKER *utp, FLOWKEY *keyp, UT_TYPE *retval);
void ut_stats(UNIQUE_TRACKER *utp, int dumpall);
int ut_memcap(UNIQUE_TRACKER *utp);
int ut_row_count(UNIQUE_TRACKER *utp);
int ut_overhead_bytes(UNIQUE_TRACKER *sbp);
#endif /* _UNIQUE_TRACKER_H */

