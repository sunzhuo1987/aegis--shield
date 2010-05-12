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
 * @file   flow_packet.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Wed Jun 25 09:20:41 2003
 * 
 * @brief  interface for packet structures between snort and flow
 *
 *
 * Camel Hump notation for cleaner integration w/ snort
 * 
 * 
 */

#ifndef _FLOW_PACKET_H
#define _FLOW_PACKET_H

#include "decode.h"
#include "common_defs.h"
#include <string.h>

typedef Packet FLOWPACKET;

/** 
 * Determine if this is an IPV4 packet
 * 
 * @param p packet to determine if it's ipv4
 * 
 * @return 1 if it is an IPv4 Packet, 0 otherwise
 */
static int INLINE IsIPv4Packet(FLOWPACKET *p)
{
    FLOWASSERT(p);

    if(p && p->iph)
        return 1;
    
    return 0;
}

/** 
 * Determine if this is an Tcp packet
 * 
 * @param p packet to determine if it's tcp
 * 
 * @return 1 if it is an tcp Packet, 0 otherwise
 */
static int INLINE IsTcpPacket(FLOWPACKET *p)
{
    FLOWASSERT(p);

    if(p && p->tcph)
        return 1;

    return 0;
}

/** 
 * Determine if this is an Tcp packet
 * 
 * @param p packet to determine if it's tcp
 * 
 * @return 1 if it is an tcp Packet, 0 otherwise
 */
static u_int8_t INLINE GetTcpFlags(FLOWPACKET *p)
{
    FLOWASSERT(p && p->tcph);
    
    if(p && p->tcph)
        return p->tcph->th_flags;

    return 0;
}


/** 
 * Returns the Source Port portion of a packet in host byte
 * order.
 *
 * This function assumes that there this packet is has been properly
 * identified to contain an IPv4 Header.
 * 
 * @param p packet 
 * 
 * @return the sport || 0
 */
static u_int16_t INLINE GetIPv4SrcPort(FLOWPACKET *p)     
{
    FLOWASSERT(p);

    if(p)
        return p->sp;

    return 0;
}


/** 
 * Returns the Destination Port portion of a packet in host byte
 * order.
 *
 * This function assumes that there this packet is has been properly
 * identified to contain an IPv4 Header.
 * 
 * @param p packet 
 * 
 * @return the sport || 0
 */
static u_int16_t INLINE GetIPv4DstPort(FLOWPACKET *p)     
{
    FLOWASSERT(p);
    
    if(p)
        return p->dp;

    return 0;
}


/** 
 * Returns the IP Protocol portion of a packet.
 *
 * This function assumes that there this packet is has been properly
 * identified to contain an IPv4 Header.
 * 
 * @param p packet 
 * 
 * @return the sport || 0
 */
static u_int8_t INLINE GetIPv4Proto(FLOWPACKET *p)     
{
    FLOWASSERT(p && p->iph);
        
    if(p && p->iph)
        return p->iph->ip_proto;

    return 0;
}

/** 
 * Returns the SIP portion of a packet.
 *
 * This function assumes that there this packet is has been properly
 * identified to contain an IPv4 Header.
 *
 * This performs memcpy's incase the IPH is not aligned in snort.
 * 
 * @param p packet 
 * 
 * @return the sport || 0
 */
static u_int32_t INLINE GetIPv4SrcIp(FLOWPACKET *p)     
{
    FLOWASSERT(p && p->iph);
    
    if(p && p->iph)
        return p->iph->ip_src.s_addr;
    
    return 0;
}


/** 
 * Returns the DIP portion of a packet.
 *
 * This function assumes that there this packet is has been properly
 * identified to contain an IPv4 Header.
 *
 * This performs memcpy's incase the IPH is not aligned in snort.
 * 
 * @param p packet 
 * 
 * @return the sport || 0
 */
static u_int32_t INLINE GetIPv4DstIp(FLOWPACKET *p)     
{
    FLOWASSERT(p && p->iph);
    
    if(p && p->iph)
        return p->iph->ip_dst.s_addr;

    return 0;
}


/** 
 * Get the IP length of a packet.  
 * 
 * @param p packet to operate on
 * 
 * @return size of the packet
 */
static int INLINE GetIPv4Len(FLOWPACKET *p)
{
    FLOWASSERT(p);

    if(p)
    {
        if(p->iph)
            return ntohs(p->iph->ip_len);
        else
            return p->dsize;
    }

    return 0;
}



#endif /* _FLOW_PACKET_H */

