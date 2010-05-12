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
 
#ifndef _FLOW_STAT_H
#define _FLOW_STAT_H

#include <stdio.h>
#include <time.h>

#include "flow.h"

int flowstat_clear(FLOWSTATS *fsp);
int flowstat_print(FLOWSTATS *fsp);
int flowstat_increment(FLOWSTATS *fsp, int direction, time_t cur, u_int32_t bytes);
int flowstat_callback(FLOW_POSITION position, FLOW *flow, int direction, time_t cur, FLOWPACKET *p);
#endif /* _FLOW_STAT_H */
