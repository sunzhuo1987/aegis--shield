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
 
/**
 * @file   scoreboard.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Thu Jun  5 09:46:58 2003
 * 
 * @brief  implementation of a autorecovery scoreboard
 * 
 * Right now, there are two tables and memory is shared between them
 * both.  In the future, they should really share the same memory pool
 * and the free lists should have some method for figuring out which
 * one a node belongs in.
 *
 * @todo add a list of the last nodes I've talked to
 */

#ifndef _SCOREBOARD_H
#define _SCOREBOARD_H

#include "flowps.h"
#include "sfxhash.h"



#define PSENTRY_NEW     0x0001
#define PSENTRY_SLIDING 0x0002

/**
 * this is the data for an individual tracker
 *
 * currenly, all score board items have a score and 2 time's that may
 * be used for the time scale.
 */


int scoreboard_init(SCOREBOARD *sbp,
                    char *description,
                    TRACKER_POSITION kind,
                    unsigned int rows,  int memcap);

int scoreboard_destroy(SCOREBOARD *sbp);
int scoreboard_add(SCOREBOARD *sbp, u_int32_t *address, SCORE_ENTRY **sepp);
int scoreboard_find(SCOREBOARD *sbp, u_int32_t *address, SCORE_ENTRY **sepp);
int scoreboard_remove(SCOREBOARD *sbp, u_int32_t *address);

int scoreboard_move(SCOREBOARD *dst, SCOREBOARD *src, u_int32_t *address);

int scoreboard_memcap(SCOREBOARD *sbp);
int scoreboard_row_count(SCOREBOARD *sbp);
int scoreboard_overhead_bytes(SCOREBOARD *sbp);
void scoreboard_stats(SCOREBOARD *sbp, int dumpall);

#endif /* _SCOREBOARD_H */
