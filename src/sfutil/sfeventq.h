/****************************************************************************
 *
 * Copyright (C) 2004-2008 Sourcefire, Inc.
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
 
#ifndef __SF_EVENTQ_H__
#define __SF_EVENTQ_H__

void *sfeventq_event_alloc(void);
void  sfeventq_reset(void);
int   sfeventq_add(void *event);
int   sfeventq_action(int (*action_func)(void *event, void *user), void *user);
int   sfeventq_init(int max_nodes, int log_nodes, int event_size, 
                    int (*sort)(void *, void *));
void sfeventq_free(void);

#endif
