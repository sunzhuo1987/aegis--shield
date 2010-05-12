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
 
#include "flow_class.h"
#include "flow_error.h"

/** 
 * Find the relevant flow processing scheme for a packet
 * 
 * @param p packet to find the flow scheme for
 * 
 * @return 0 on success, 1 on failure
 */
int flow_classifier(FLOWPACKET *p, int *flowtype)
{
    if(p == NULL)
    {
        return FLOW_ENULL;
    }

    if(IsIPv4Packet(p))
    {
        *flowtype = FLOW_IPV4;            
        return FLOW_SUCCESS;
    }

    return FLOW_EINVALID;
}
