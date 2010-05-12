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
 
#ifndef _FLOW_CALLBACK_H
#define _FLOW_CALLBACK_H

#include "flow.h"
#include "flow_cache.h"

typedef struct _FLOWCALLBACKDATA
{
    char use_once;
    /* do the matching on the initiator side of a conversation */
    u_int32_t resp_address;
    u_int32_t resp_port;
    /* do the matching on the reponder side of a conversation */

    u_int32_t init_address;
    u_int32_t init_port;
    
    time_t expiration;    
    unsigned char postition; /* where in the flow back module we should be called */
    unsigned char order;     /* when sorting out the callbacks, 0,1,2... undefined between the same orders */
    // int (*flow_callback)(int position, FLOW *flow, int direction, Packet *p);
} FLOWCALLBACKDATA;

int flow_callbacks(FLOW_POSITION position, FLOW *flowp, int direction, FLOWPACKET *p);

#endif /* _FLOW_CALLBACK_H */
