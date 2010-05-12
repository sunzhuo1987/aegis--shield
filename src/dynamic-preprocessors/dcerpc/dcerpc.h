/*
 * dcerpc.h
 *
 * Copyright (C) 2006-2008 Sourcefire, Inc.
 * Andrew Mullican
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
 * Description:
 *
 * Declares routines that handle decoding DCERPC packets.
 *
 *
 */
#ifndef _DCERPC_H_
#define _DCERPC_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#pragma pack(push,dce_hdrs,1)
#else
#pragma pack(1)
#endif

#define DCERPC_SEGMENTED         1
#define DCERPC_FULL_FRAGMENT     2
#define DCERPC_FRAG_REASSEMBLED  3
#define DCERPC_FRAGMENT          4

typedef struct dcerpc_hdr
{
    u_int8_t  version;
    u_int8_t  version_minor;
    u_int8_t  packet_type;
    u_int8_t  flags;
    u_int8_t  byte_order;
    u_int8_t  floating_point;
    u_int16_t padding;

    u_int16_t frag_length;
    u_int16_t auth_length;
    u_int32_t call_id;

} DCERPC_HDR;

typedef struct dcerpc_req
{
    DCERPC_HDR  dcerpc_hdr;
    u_int32_t   alloc_hint;
    u_int16_t   context_id;
    u_int16_t   opnum;

} DCERPC_REQ;

/* Packet types */
#define DCERPC_REQUEST   0
#define DCERPC_BIND     11

/* Packet flags */
#define DCERPC_FIRST_FRAG   0x01
#define DCERPC_LAST_FRAG    0x02

#define DCERPC_FRAG_ALLOC   2

/* PIPE function */
#define DCERPC_PIPE     0x0026

#define DCERPC_BYTE_ORDER(byte_order_flag) ((u_int8_t)byte_order_flag & 0xF0) >> 4

#ifdef WORDS_BIGENDIAN

#define dcerpc_ntohs(byte_order_flag, value) \
(DCERPC_BYTE_ORDER(byte_order_flag) == 0 ? (u_int16_t)(value) : \
 (((u_int16_t)(value) & 0xff00) >> 8) | (((u_int16_t)(value) & 0x00ff) << 8))

#define dcerpc_ntohl(byte_order_flag, value) \
(DCERPC_BYTE_ORDER(byte_order_flag) == 0 ? (u_int32_t)(value) : \
 (((u_int32_t)(value) & 0xff000000) >> 24) | (((u_int32_t)(value) & 0x00ff0000) >> 8) | \
 (((u_int32_t)(value) & 0x0000ff00) << 8) | (((u_int32_t)(value) & 0x000000ff) << 24))

#else

#define dcerpc_ntohs(byte_order_flag, value) \
(DCERPC_BYTE_ORDER(byte_order_flag) == 1 ? (u_int16_t)(value) : \
 (((u_int16_t)(value) & 0xff00) >> 8) | (((u_int16_t)(value) & 0x00ff) << 8))

#define dcerpc_ntohl(byte_order_flag, value) \
(DCERPC_BYTE_ORDER(byte_order_flag) == 1 ? (u_int32_t)(value) : \
 (((u_int32_t)(value) & 0xff000000) >> 24) | (((u_int32_t)(value) & 0x00ff0000) >> 8) | \
 (((u_int32_t)(value) & 0x0000ff00) << 8) | (((u_int32_t)(value) & 0x000000ff) << 24))

#endif  /* WORDS_BIGENDIAN */

#define dcerpc_htons dcerpc_ntohs
#define dcerpc_htonl dcerpc_ntohl


int IsCompleteDCERPCMessage(const u_int8_t *, u_int16_t);
int ProcessDCERPCMessage(const u_int8_t *, u_int16_t, const u_int8_t *, u_int16_t);

void ReassembleDCERPCRequest(const u_int8_t *, u_int16_t, const u_int8_t *);
int DCERPC_Fragmentation(const u_int8_t *, u_int16_t, u_int16_t);


#ifdef WIN32
#pragma pack(pop,dce_hdrs)
#else
#pragma pack()
#endif

#endif  /* _DCERPC_H_  */

