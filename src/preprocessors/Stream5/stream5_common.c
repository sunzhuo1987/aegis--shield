/****************************************************************************
 *
 * Copyright (C) 2005-2008 Sourcefire, Inc.
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
 
#include "debug.h"
#include "decode.h"
#include "generators.h"
#include "event_queue.h"
#include "snort.h"
#include "sf_types.h"

#include "stream5_common.h"

/*  M A C R O S  **************************************************/
INLINE UINT64 CalcJiffies(Packet *p)
{
    UINT64 ret = 0;
    UINT64 sec = (p->pkth->ts.tv_sec * TCP_HZ);
    UINT64 usec = (p->pkth->ts.tv_usec / (1000000UL/TCP_HZ));

    ret = sec + usec;

    return ret;
    //return (p->pkth->ts.tv_sec * TCP_HZ) + 
    //       (p->pkth->ts.tv_usec / (1000000UL/TCP_HZ));
}

int Stream5Expire(Packet *p, Stream5LWSession *lwssn)
{
    UINT64 pkttime = CalcJiffies(p);

    if (lwssn->expire_time == 0)
    {
        /* Not yet set, not expired */
        return 0;
    }
    
    if((int)(pkttime - lwssn->expire_time) > 0)
    {
        sfPerf.sfBase.iStreamTimeouts++;
        lwssn->session_flags |= SSNFLAG_TIMEDOUT;
        lwssn->session_state |= STREAM5_STATE_TIMEDOUT;

        switch (lwssn->protocol)
        {
            case IPPROTO_TCP:
                s5stats.tcp_timeouts++;
                //DeleteLWSession(tcp_lws_cache, lwssn);
                break;
            case IPPROTO_UDP:
                s5stats.udp_timeouts++;
                //DeleteLWSession(udp_lws_cache, lwssn);
                break;
            case IPPROTO_ICMP:
                s5stats.icmp_timeouts++;
                //DeleteLWSession(icmp_lws_cache, lwssn);
                break;
        }
        return 1;
    }

    return 0;
}

void Stream5SetExpire(Packet *p, 
        Stream5LWSession *lwssn, u_int32_t timeout)
{
    lwssn->expire_time = CalcJiffies(p) + (timeout * TCP_HZ);
    return;
}

void MarkupPacketFlags(Packet *p, Stream5LWSession *lwssn)
{
    if(!lwssn)
        return;

    if((lwssn->session_flags & SSNFLAG_ESTABLISHED) != SSNFLAG_ESTABLISHED)
    {
        if((lwssn->session_flags & (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT)) ==
            (SSNFLAG_SEEN_SERVER|SSNFLAG_SEEN_CLIENT))
        {
            p->packet_flags |= PKT_STREAM_UNEST_BI;
        }
        else
        {
            p->packet_flags |= PKT_STREAM_UNEST_UNI;
        }
    }
    else
    {
        p->packet_flags |= PKT_STREAM_EST;
        if(p->packet_flags & PKT_STREAM_UNEST_UNI)
        {
            p->packet_flags ^= PKT_STREAM_UNEST_UNI;
        }
    }
}
