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
 
#ifndef _EVENT_WRAPPER_H
#define _EVENT_WRAPPER_H

#include "log.h"
#include "detect.h"
#include "decode.h"
#include "rules.h"

/* 
 * this has been upgarded to reroute traffic to fpLogEvent() 
 * to add support for thresholding, and other rule behaviors 
 * like drop,alert.  This has been updated to allow decoder events
 * which call it to be filtered through fpLogEvent.  This of course
 * requires a rule be writen for each decoder event, and preprocssor event,
 * although preprocessors don't seem to use this much.
 */
u_int32_t GenerateSnortEvent(Packet *p,
                            u_int32_t gen_id,
                            u_int32_t sig_id,
                            u_int32_t sig_rev,
                            u_int32_t classification,
                            u_int32_t priority,
                            char *msg);

OptTreeNode * GenerateSnortEventOtn(
                            u_int32_t gen_id,
                            u_int32_t sig_id,
                            u_int32_t sig_rev,
                            u_int32_t classification,
                            u_int32_t priority,
                            char *msg );

int LogTagData(Packet *p,
               u_int32_t gen_id,
               u_int32_t sig_id,
               u_int32_t sig_rev,
               u_int32_t classification,
               u_int32_t priority,
               u_int32_t event_ref,
               time_t ref_sec,
               char *msg);

#endif /* _EVENT_WRAPPER_H */
